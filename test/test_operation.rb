# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'
require 'thread'

# Deterministic, sleep-free tests for concurrent (multiplexed) LDAP
# operations. A single ScriptedSocket feeds BER PDUs to the connection's
# single BER reader; the tests interleave two searches, a compare and a
# cancel and assert how replies are attributed to message IDs.
class TestConcurrentOperations < Test::Unit::TestCase
  # A socket double whose incoming bytes are whole PDUs taken from a Queue.
  # #read_ber blocks until the test pushes the next PDU, so ordering is
  # controlled entirely by Queue synchronization - no sleeps.
  class ScriptedSocket
    def initialize
      @incoming = Queue.new
      @written = Queue.new
      @reader_io, @writer_io = IO.pipe
    end

    attr_reader :incoming, :written

    # IO.select watches this end; push() writes a byte to wake selectors.
    attr_reader :reader_io

    def read_ber(_syntax = nil)
      # Block on the queue; the readiness pipe is only used by callers that
      # need IO.select-based timeouts (see #read_ber_with_timeout).
      @incoming.pop
    rescue ClosedQueueError
      nil
    end

    # Variant used by Connection#read_with_timeout: wait for the readiness
    # signal up to +timeout+ seconds, then pop without blocking.
    def read_ber_with_timeout(_syntax = nil, timeout = nil)
      ready = IO.select([@reader_io], nil, nil, timeout)
      return :read_timeout unless ready
      @reader_io.read_nonblock(1, exception: :wait) rescue nil
      begin
        @incoming.pop(true)
      rescue ThreadError
        nil
      end
    end

    def write(bytes)
      @written << bytes
      bytes.bytesize
    end

    def close
      @incoming.close unless @incoming.closed?
      @reader_io.close unless @reader_io.closed?
      @writer_io.close unless @writer_io.closed?
    end

    def push(pdu)
      @incoming << pdu
      @writer_io.write_nonblock("\0", exception: false)
    end
  end

  def setup
    @socket = ScriptedSocket.new
    @connection = Net::LDAP::Connection.new(:socket => @socket)
  end

  def teardown
    @connection.close
  end

  # Build a BER PDU the way the wire would carry it.
  def pdu(message_id, app_tag, *ldap_result)
    result = Net::BER::BerIdentifiedArray.new(ldap_result)
    result.ber_identifier = app_tag
    [message_id, result]
  end

  def search_result(message_id, code = Net::LDAP::ResultCodeSuccess,
                    error_message = "")
    pdu(message_id, Net::LDAP::PDU::SearchResult, code, "", error_message)
  end

  def compare_response(message_id, code)
    pdu(message_id, Net::LDAP::PDU::CompareResponse, code, "", "")
  end

  def extended_response(message_id, code, error_message = "")
    pdu(message_id, Net::LDAP::PDU::ExtendedResponse, code, "", error_message)
  end

  def search_entry(message_id, dn, attributes = { "uid" => ["#{dn}-uid"] })
    attr_ber = attributes.map { |name, values| [name, values] }
    entry = Net::BER::BerIdentifiedArray.new([dn, attr_ber])
    entry.ber_identifier = Net::LDAP::PDU::SearchReturnedData
    [message_id, entry]
  end

  def written_requests
    requests = []
    loop do
      begin
        requests << @socket.written.pop(true)
      rescue ThreadError
        break
      end
    end
    requests
  end

  def message_ids_written
    written_requests.map do |bytes|
      StringIO.new(bytes).read_ber(envelope_syntax)[0]
    end
  end

  # Parse only the envelope message ID without interpreting the request
  # body (which may use shapes the default LDAP syntax does not know, such
  # as the RFC 3909 Cancel value).
  def envelope_syntax
    @envelope_syntax ||= Net::BER.compile_syntax(
      application: {
        primitive: (0..30).each_with_object({}) { |i, h| h[i] = :string },
        constructed: (0..30).each_with_object({}) { |i, h| h[i] = :array },
      },
      universal: { constructed: { 107 => :string } },
      context_specific: {
        primitive: { 0 => :string, 1 => :string, 2 => :string,
                     3 => :string, 4 => :string, 7 => :string },
        constructed: (0..9).each_with_object({}) { |i, h| h[i] = :array },
      }
    )
  end

  # Parse an encoded cancel extended request and return the message ID it
  # asks the server to cancel.
  def cancel_target(bytes)
    parsed = StringIO.new(bytes).read_ber(envelope_syntax)
    parsed[1][1]
  end

  # Two searches and a compare are interleaved. The short compare and the
  # second search complete while the first search is still streaming.
  def test_short_operations_complete_while_a_long_search_streams
    long  = @connection.begin_search(base: "dc=example,dc=org",
                                   filter: "(objectClass=*)")
    other = @connection.begin_search(base: "dc=example,dc=org",
                                    filter: "(uid=other)")
    short = @connection.begin_compare(dn: "uid=george,ou=People,dc=example,dc=org",
                                     attribute: "uid", value: "george")

    assert_equal 1, long.message_id
    assert_equal 2, other.message_id
    assert_equal 3, short.message_id

    # Server interleaves: an entry for the long search, then the compare
    # response (short operation finishes first), then another search entry.
    @socket.push(search_entry(1, "uid=george,ou=People,dc=example,dc=org"))
    @socket.push(compare_response(3, Net::LDAP::ResultCodeCompareTrue))
    @socket.push(search_entry(2, "uid=other,ou=People,dc=example,dc=org"))

    # The compare result can be collected before either search terminates.
    compare_result = short.result
    assert short.finished?
    assert_equal Net::LDAP::ResultCodeCompareTrue, compare_result.result_code
    assert long.active?
    assert other.active?

    # Finish the second (short) search, then the long one.
    @socket.push(search_result(2))
    other_entries = other.to_a
    assert other.finished?
    assert_equal ["uid=other,ou=People,dc=example,dc=org"],
                 other_entries.map(&:dn)
    assert long.active?

    @socket.push(search_entry(1, "uid=martha,ou=People,dc=example,dc=org"))
    @socket.push(search_result(1))
    long_entries = long.to_a
    assert long.finished?
    assert_equal ["uid=george,ou=People,dc=example,dc=org",
                  "uid=martha,ou=People,dc=example,dc=org"],
                 long_entries.map(&:dn)
    assert_equal 2, long.entry_count
  end

  # Canceling one search must not swallow entries belonging to the other
  # search. The cancel request's own result and the canceled operation's
  # termination result are tracked separately.
  def test_cancel_one_search_does_not_affect_the_other
    long  = @connection.begin_search(base: "dc=example,dc=org",
                                    filter: "(objectClass=*)")
    other = @connection.begin_search(base: "dc=example,dc=org",
                                    filter: "(uid=keep)")

    cancel = long.cancel
    assert_equal 3, cancel.message_id
    written = written_requests
    ids = written.map do |bytes|
      StringIO.new(bytes).read_ber(envelope_syntax)[0]
    end
    assert_equal [1, 2, 3], ids
    assert_equal 1, cancel_target(written.last)

    # Server acknowledges the cancel request itself...
    @socket.push(extended_response(3, Net::LDAP::ResultCodeSuccess))
    cancel_result = cancel.result
    assert_equal Net::LDAP::ResultCodeSuccess, cancel_result.result_code

    # ...and terminates the original search with canceled (118).
    @socket.push(search_result(1, Net::LDAP::ResultCodeCanceled))
    long_result = long.result
    assert_equal Net::LDAP::ResultCodeCanceled, long_result.result_code
    assert long.canceled?

    # Entries for the still-outstanding second search keep flowing.
    @socket.push(search_entry(2, "uid=keep,ou=People,dc=example,dc=org"))
    @socket.push(search_result(2))
    entries = other.to_a
    assert other.finished?
    assert_equal ["uid=keep,ou=People,dc=example,dc=org"],
                 entries.map(&:dn)
    assert_equal 1, other.entry_count
  end

  # RFC 3909: the cancel request's own result and the target operation's
  # termination result are tracked independently on distinct operations.
  def test_cancel_request_result_is_separate_from_target_result
    target = @connection.begin_search(base: "dc=example,dc=org",
                                     filter: "(uid=t)")
    cancel = target.cancel

    refute_same target, cancel
    assert_equal 1, target.message_id
    assert_equal 2, cancel.message_id
    assert target.active?
    assert cancel.active?

    # Server answers the cancel request with cannotCancel (120): that marks
    # only the cancel operation; the target keeps running.
    @socket.push(extended_response(2, Net::LDAP::ResultCodeCannotCancel,
                                  "cannot cancel"))
    cancel_result = cancel.result
    assert_equal Net::LDAP::ResultCodeCannotCancel,
                 cancel_result.result_code
    assert target.active?
    refute target.canceled?

    # The target then terminates on its own with a normal success result.
    @socket.push(search_result(1, Net::LDAP::ResultCodeSuccess))
    assert_equal Net::LDAP::ResultCodeSuccess,
                 target.result.result_code
    assert target.finished?
    refute target.canceled?
  end

  # A second #cancel call on an already-canceled operation returns the same
  # cancel operation and never sends another request.
  def test_cancel_is_idempotent
    target = @connection.begin_search(base: "dc=example,dc=org",
                                     filter: "(uid=t)")
    first = target.cancel
    second = target.cancel
    assert_same first, second

    written = written_requests
    assert_equal 2, written.size # search + a single cancel
  end

  # After an operation finishes, a late entry carrying its message ID must
  # not be delivered anywhere - and because message IDs are never reused it
  # cannot land in a new operation either.
  def test_late_entries_are_not_delivered_to_finished_or_reused_ids
    op = @connection.begin_search(base: "dc=example,dc=org",
                                  filter: "(uid=x)")
    @socket.push(search_entry(1, "uid=x,ou=People,dc=example,dc=org"))
    @socket.push(search_result(1))
    entries = op.to_a
    assert op.finished?
    assert_equal ["uid=x,ou=People,dc=example,dc=org"], entries.map(&:dn)

    # A new operation gets a fresh, higher message ID.
    later = @connection.begin_search(base: "dc=example,dc=org",
                                    filter: "(uid=y)")
    assert_equal 2, later.message_id

    # Late entries for the finished ID 1 are dropped (instrumented, not
    # raised); the new operation with ID 2 is unaffected.
    @socket.push(search_entry(1, "uid=LATE,ou=People,dc=example,dc=org"))
    @socket.push(search_entry(2, "uid=y,ou=People,dc=example,dc=org"))
    @socket.push(search_result(2))

    later_entries = later.to_a
    assert_equal ["uid=y,ou=People,dc=example,dc=org"],
                 later_entries.map(&:dn)
    assert_equal 1, later.entry_count
    assert_equal 1, op.entry_count
  end

  # Message ID 0 is an unsolicited notification: it is never attributed to
  # any request, even while operations are outstanding.
  def test_unsolicited_notification_never_matches_a_request
    op = @connection.begin_search(base: "dc=example,dc=org",
                                  filter: "(uid=z)")

    received = Queue.new
    @connection.on_unsolicited_notification { |pdu| received << pdu }

    notice = pdu(0, Net::LDAP::PDU::ExtendedResponse,
                 Net::LDAP::ResultCodeOther, "", "notice")
    @socket.push(notice)
    @socket.push(search_entry(1, "uid=z,ou=People,dc=example,dc=org"))
    @socket.push(search_result(1))

    assert_equal 1, op.to_a.size
    assert op.finished?

    unsolicited = received.pop
    assert_equal 0, unsolicited.message_id
    assert_equal "notice", unsolicited.error_message
    assert_equal 1, @connection.unsolicited_notifications.size
  end

  # Closing the connection while operations are outstanding gives each its
  # own terminal result rather than sharing one or leaving callers blocked.
  def test_closing_finalizes_every_outstanding_operation
    long  = @connection.begin_search(base: "dc=example,dc=org",
                                    filter: "(objectClass=*)")
    short = @connection.begin_compare(dn: "uid=george,ou=People,dc=example,dc=org",
                                     attribute: "uid", value: "george")
    @socket.push(search_entry(1, "uid=george,ou=People,dc=example,dc=org"))

    # Drive the single reader so the buffered entry is delivered, but keep
    # the operations without terminal results. Each entry stream ends with
    # a sentinel; only non-sentinel values are real entries.
    entry = long.next_entry
    assert_equal "uid=george,ou=People,dc=example,dc=org", entry.dn
    assert long.active?
    assert short.active?

    @connection.close

    assert long.finished?
    assert short.finished?
    assert long.connection_closed?
    assert short.connection_closed?
    assert_equal Net::LDAP::ResultCodeConnectionClosed,
                 long.result.result_code
    assert_equal Net::LDAP::ResultCodeConnectionClosed,
                 short.result.result_code
    # Buffered entries remain consumable after close.
    assert_nil long.next_entry
  end

  # The blocking #compare path can be interleaved with an outstanding
  # search started through the concurrent API.
  def test_blocking_compare_interleaves_with_outstanding_search
    long = @connection.begin_search(base: "dc=example,dc=org",
                                   filter: "(objectClass=*)")
    assert_equal 1, long.message_id

    started = Queue.new
    compare_thread = Thread.new do
      started << :go
      @connection.compare(dn: "uid=george,ou=People,dc=example,dc=org",
                          attribute: "uid", value: "george")
    end
    started.pop
    # Wait (via Queue, not sleep) until both requests are written.
    ids = []
    ids << StringIO.new(@socket.written.pop).read_ber(Net::LDAP::AsnSyntax)[0]
    ids << StringIO.new(@socket.written.pop).read_ber(Net::LDAP::AsnSyntax)[0]
    assert_equal [1, 2], ids.sort

    # Compare got message ID 2; reply out of order while search runs.
    @socket.push(compare_response(2, Net::LDAP::ResultCodeCompareFalse))
    compare_pdu = compare_thread.value
    assert_equal Net::LDAP::ResultCodeCompareFalse,
                 compare_pdu.result_code

    @socket.push(search_result(1))
    assert_equal Net::LDAP::ResultCodeSuccess, long.result.result_code
  end

  # next_entry blocks cooperatively (driving the reader) until an entry or
  # the terminal result arrives, and returns nil after exhaustion.
  def test_next_entry_streams_and_ends
    op = @connection.begin_search(base: "dc=example,dc=org",
                                  filter: "(uid=n)")
    @socket.push(search_entry(1, "uid=n1,ou=People,dc=example,dc=org"))
    assert_equal "uid=n1,ou=People,dc=example,dc=org", op.next_entry.dn
    @socket.push(search_result(1))
    assert_nil op.next_entry
  end

  def test_result_timeout_raises
    op = @connection.begin_search(base: "dc=example,dc=org",
                                  filter: "(uid=t)")
    # No server replies are pushed, so the operation never terminates.
    # The timeout still bounds the wait without requiring any data to flow.
    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_raise Net::LDAP::OperationTimeoutError do
      op.result(0.05)
    end
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
    assert elapsed < 2.0, "timeout took too long: #{elapsed}"
    @connection.close # teardown would otherwise block
  end
end

# End-to-end tests through the public Net::LDAP facade.
class TestConcurrentOperationsFacade < Test::Unit::TestCase
  def compare_response(message_id, code)
    result = Net::BER::BerIdentifiedArray.new([code, "", ""])
    result.ber_identifier = Net::LDAP::PDU::CompareResponse
    [message_id, result]
  end

  def search_result(message_id)
    result = Net::BER::BerIdentifiedArray.new([Net::LDAP::ResultCodeSuccess, "", ""])
    result.ber_identifier = Net::LDAP::PDU::SearchResult
    [message_id, result]
  end

  def test_search_operation_and_compare_via_public_api
    # With a pre-set open connection there is no separate bind; the search
    # gets message ID 1 and the compare ID 2.
    socket = TestConcurrentOperations::ScriptedSocket.new
    ldap = Net::LDAP.new(host: "example.org", force_no_page: true,
                        auth: { method: :anonymous })
    ldap.connection = Net::LDAP::Connection.new(:socket => socket)

    search = ldap.search_operation(base: "dc=example,dc=org",
                                   ignore_server_caps: true)
    compare = ldap.compare_operation(dn: "uid=george,dc=example,dc=org",
                                    attribute: "uid", value: "george")

    socket.push(compare_response(2, Net::LDAP::ResultCodeCompareTrue))
    socket.push(search_result(1))

    assert_equal Net::LDAP::ResultCodeCompareTrue, compare.result.result_code
    assert_equal Net::LDAP::ResultCodeSuccess, search.result.result_code
  end
end
