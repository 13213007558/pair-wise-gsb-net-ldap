# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'

# Tests for the explicit concurrent-operation interface. These tests use a
# scripted fake socket: each PDU is pushed in a fixed order, and the test
# drives the connection by waiting on operations. No threads and no sleeps
# are involved, so the interleaving order is deterministic.
class TestLDAPOperations < Test::Unit::TestCase
  # Socket whose BER responses come from a pre-arranged queue. Writes are
  # captured for assertion.
  class ScriptedSocket
    attr_reader :written

    def initialize(responses)
      @responses = responses
      @written = []
    end

    def write(data)
      @written << data
      data.bytesize
    end

    def read_ber(_syntax = nil)
      response = @responses.shift
      return response unless response.is_a?(String)
      response.read_ber(Net::LDAP::AsnSyntax)
    end

    def close; end
  end

  def setup
    @responses = []
    @socket = ScriptedSocket.new(@responses)
    @connection = Net::LDAP::Connection.new(:socket => @socket)
  end

  # Build a raw BER object the BER parser would produce.
  def result_pdu(message_id, app_tag, code = Net::LDAP::ResultCodeSuccess,
                matched_dn: "", error_message: "")
    values = [code.to_ber_enumerated, matched_dn.to_ber, error_message.to_ber]
    inner = values.to_ber_appsequence(app_tag)
    [message_id.to_ber, inner].to_ber_sequence
  end

  def entry_pdu(message_id, dn, attributes = { "cn" => ["value"] })
    attrs = attributes.map do |name, values|
      [name.to_ber, Array(values).map { |v| v.to_ber }.to_ber_set]
    end
    inner = [dn.to_ber, attrs.to_ber_sequence].to_ber_appsequence(Net::LDAP::PDU::SearchReturnedData)
    [message_id.to_ber, inner].to_ber_sequence
  end

  def referral_pdu(message_id, uris)
    inner = Array(uris).map(&:to_ber).to_ber_appsequence(Net::LDAP::PDU::SearchResultReferral)
    [message_id.to_ber, inner].to_ber_sequence
  end

  def search_args(overrides = {})
    {
      base: "ou=People,dc=example,dc=org",
      filter: Net::LDAP::Filter.eq("uid", "user1"),
    }.merge(overrides)
  end

  # Decode the written packet with the given index and return its inner
  # application tag and request body.
  def parse_written(index)
    packet = @socket.written[index].read_ber(Net::LDAP::AsnSyntax)
    inner = packet[1]
    [inner.ber_identifier & 0x1f, packet, inner]
  end

  def test_interleaved_search_search_compare_and_cancel
    long  = @connection.start_search(search_args)
    short = @connection.start_search(search_args)
    compare = @connection.start_compare(
      dn: "uid=user1,ou=People,dc=example,dc=org",
      attribute: "uid",
      value: "user1",
    )

    assert_equal 1, long.message_id
    assert_equal 2, short.message_id
    assert_equal 3, compare.message_id

    # Server pushes entries and results in an interleaved order. The long
    # search only sends an entry; the short compare result arrives first.
    @responses << entry_pdu(long.message_id, "uid=long,ou=People", "cn" => ["long1"])
    @responses << result_pdu(compare.message_id, Net::LDAP::PDU::CompareResponse,
                             Net::LDAP::ResultCodeCompareTrue)
    @responses << entry_pdu(short.message_id, "uid=short,ou=People", "cn" => ["short1"])
    @responses << result_pdu(short.message_id, Net::LDAP::PDU::SearchResult)

    compare_result = compare.wait

    assert compare_result.success?
    assert_equal Net::LDAP::ResultCodeCompareTrue, compare_result.result_code

    short_result = short.wait
    assert short_result.success?
    short_entries = short.drain_entries
    assert_equal ["uid=short,ou=People"], short_entries.map(&:dn)

    # The long search has not finished; its entry was buffered and the
    # other operations did not consume it.
    long_entries = long.drain_entries
    assert_equal ["uid=long,ou=People"], long_entries.map(&:dn)
    refute long.finished?

    # Cancel the long search. Its cancel request and its termination are
    # tracked independently.
    cancel_operation = long.cancel
    assert_equal 4, cancel_operation.message_id

    # The cancel request's own result and the target operation's
    # termination result are separate PDUs, separately tracked.
    @responses << result_pdu(cancel_operation.message_id,
                             Net::LDAP::PDU::ExtendedResponse)
    @responses << result_pdu(long.message_id, Net::LDAP::PDU::SearchResult,
                             Net::LDAP::ResultCodeCanceled,
                             error_message: "canceled")
    assert cancel_operation.wait.success?
    long_result = long.wait
    assert_equal Net::LDAP::ResultCodeCanceled, long_result.result_code
    assert long.cancelled?
    assert short_result.success?
  end

  def test_cancel_does_not_swallow_entries_of_other_search
    canceled = @connection.start_search(search_args)
    survivor = @connection.start_search(search_args)

    cancel = canceled.cancel

    @responses << result_pdu(cancel.message_id, Net::LDAP::PDU::ExtendedResponse)
    @responses << entry_pdu(survivor.message_id, "uid=keep,ou=People", "cn" => ["keep1"])
    @responses << result_pdu(canceled.message_id, Net::LDAP::PDU::SearchResult,
                             Net::LDAP::ResultCodeCanceled)
    @responses << entry_pdu(survivor.message_id, "uid=keep2,ou=People", "cn" => ["keep2"])
    @responses << result_pdu(survivor.message_id, Net::LDAP::PDU::SearchResult)

    assert cancel.wait.success?

    entries = []
    result = survivor.entries { |entry| entries << entry.dn }

    assert result.success?
    assert_equal ["uid=keep,ou=People", "uid=keep2,ou=People"], entries
    assert_equal Net::LDAP::ResultCodeCanceled, canceled.wait.result_code
  end

  def test_cancel_request_is_rfc3909_extended_request
    search = @connection.start_search(search_args)
    search.cancel

    # written[0] is the search request; written[1] is the cancel request.
    app_tag, packet, inner = parse_written(1)
    assert_equal Net::LDAP::PDU::ExtendedRequest, app_tag
    assert_equal Net::LDAP::CancelOid, inner[0]
    # requestValue is [1] OCTET STRING containing the target message ID.
    canceled_id = inner[1].read_ber
    assert_equal search.message_id, canceled_id
    assert_equal 2, packet[0]
  end

  def test_unsolicited_notification_message_id_zero_is_not_attributed
    search = @connection.start_search(search_args)

    notice = result_pdu(0, Net::LDAP::PDU::ExtendedResponse,
                        Net::LDAP::ResultCodeBusy, error_message: "server shutdown")
    @responses << notice
    @responses << result_pdu(search.message_id, Net::LDAP::PDU::SearchResult)

    result = search.wait

    assert result.success?
    assert_equal 1, @connection.unsolicited_notifications.size
    notification = @connection.unsolicited_notifications.first
    assert_equal 0, notification.message_id
    assert_equal Net::LDAP::ResultCodeBusy, notification.result_code
  end

  def test_late_entries_after_finish_are_not_delivered_to_reused_id
    search = @connection.start_search(search_args)

    @responses << result_pdu(search.message_id, Net::LDAP::PDU::SearchResult)
    assert search.wait.success?

    # A late entry and a late referral for the now-finished ID.
    @responses << entry_pdu(search.message_id, "uid=late,ou=People", "cn" => ["late"])
    @responses << referral_pdu(search.message_id, ["ldap://other"])

    # Pumping the late PDUs does not raise and does not deliver them.
    refute_nil @connection.pump
    refute_nil @connection.pump
    assert_empty search.drain_entries

    # A brand-new operation must be assigned a fresh ID and must never
    # receive the late traffic.
    other = @connection.start_compare(
      dn: "uid=user1,ou=People", attribute: "uid", value: "user1",
    )
    assert other.message_id > search.message_id
    @responses << result_pdu(other.message_id, Net::LDAP::PDU::CompareResponse,
                             Net::LDAP::ResultCodeCompareFalse)
    assert_equal Net::LDAP::ResultCodeCompareFalse, other.wait.result_code
    assert_empty other.drain_entries
  end

  def test_eof_finalizes_each_outstanding_operation_independently
    search_a = @connection.start_search(search_args)
    search_b = @connection.start_search(search_args)
    compare = @connection.start_compare(
      dn: "uid=user1,ou=People", attribute: "uid", value: "user1",
    )

    @responses << nil # socket EOF

    result_a = search_a.wait
    result_b = search_b.wait
    result_c = compare.wait

    [result_a, result_b, result_c].each do |pdu|
      refute pdu.success?
      assert_equal Net::LDAP::ResultCodeConnectionClosed, pdu.result_code
    end

    assert_equal search_a.message_id, result_a.message_id
    assert_equal search_b.message_id, result_b.message_id
    assert_equal compare.message_id, result_c.message_id
    assert_equal Net::LDAP::PDU::SearchResult, result_a.app_tag
    assert_equal Net::LDAP::PDU::SearchResult, result_b.app_tag
    assert_equal Net::LDAP::PDU::CompareResponse, result_c.app_tag
    assert_empty @connection.operations
  end

  def test_close_finalizes_pending_operations_without_requiring_eof
    search = @connection.start_search(search_args)
    compare = @connection.start_compare(
      dn: "uid=user1,ou=People", attribute: "uid", value: "user1",
    )

    @connection.close

    assert search.finished?
    assert compare.finished?
    assert_equal Net::LDAP::ResultCodeConnectionClosed, search.result_code
    assert_equal Net::LDAP::ResultCodeConnectionClosed, compare.result_code
    assert_equal Net::LDAP::PDU::CompareResponse, compare.result.app_tag
    assert_empty @connection.operations
  end

  def test_cancel_of_finished_operation_raises
    search = @connection.start_search(search_args)
    @responses << result_pdu(search.message_id, Net::LDAP::PDU::SearchResult)
    search.wait

    assert_raise Net::LDAP::Error do
      search.cancel
    end
  end

  def test_compare_request_encoding
    operation = @connection.start_compare(
      dn: "uid=user1,ou=People,dc=example,dc=org",
      attribute: "uid",
      value: "user1",
    )

    app_tag, _packet, inner = parse_written(0)
    assert_equal Net::LDAP::PDU::CompareRequest, app_tag
    assert_equal "uid=user1,ou=People,dc=example,dc=org", inner[0]
    attribute_value_assertion = inner[1]
    assert_equal "uid", attribute_value_assertion[0]
    assert_equal "user1", attribute_value_assertion[1]

    # The blocking compare path is tracked by its own message ID and waits
    # independently of the outstanding start_compare operation.
    @responses << result_pdu(operation.message_id, Net::LDAP::PDU::CompareResponse,
                             Net::LDAP::ResultCodeCompareFalse)
    @responses << result_pdu(operation.message_id + 1,
                             Net::LDAP::PDU::CompareResponse,
                             Net::LDAP::ResultCodeCompareTrue)
    result = @connection.compare(
      dn: "uid=user2,ou=People", attribute: "uid", value: "user2",
    )
    assert result.success?
  end

  def test_streaming_block_receives_entries_immediately
    streamed = []
    search = @connection.start_search(search_args) do |entry|
      streamed << entry.dn
    end

    @responses << entry_pdu(search.message_id, "uid=one,ou=People", "cn" => ["one"])
    @responses << entry_pdu(search.message_id, "uid=two,ou=People", "cn" => ["two"])
    @responses << result_pdu(search.message_id, Net::LDAP::PDU::SearchResult)

    result = search.wait
    assert result.success?
    assert_equal ["uid=one,ou=People", "uid=two,ou=People"], streamed
    assert_equal 2, search.entry_count
    # Entries are both streamed and retained; draining yields them once.
    assert_equal ["uid=one,ou=People", "uid=two,ou=People"],
                 search.drain_entries.map(&:dn)
    assert_empty search.drain_entries
  end

  def test_paged_search_sends_continuation_on_cookie
    operation = @connection.start_search(
      search_args(paged_searches_supported: true),
    )

    # First page: one entry and a paged-results cookie asking for more.
    control_value = [126.to_ber, "next-page".to_ber].to_ber_sequence.to_s.to_ber
    cookie_control = [
      Net::LDAP::LDAPControls::PAGED_RESULTS.to_ber,
      false.to_ber,
      control_value,
    ].to_ber_sequence
    controls_wrapper = [cookie_control].to_ber_contextspecific(0)
    first_page_result = [
      Net::LDAP::ResultCodeSuccess.to_ber_enumerated,
      "".to_ber,
      "".to_ber,
    ].to_ber_appsequence(Net::LDAP::PDU::SearchResult)
    @responses << entry_pdu(operation.message_id, "uid=one,ou=People")
    @responses << [operation.message_id.to_ber, first_page_result, controls_wrapper].to_ber_sequence

    # The continuation request is written under the same message ID before
    # the final page; deliver the second page as the terminal result.
    @responses << result_pdu(operation.message_id, Net::LDAP::PDU::SearchResult)

    entries = []
    result = operation.entries { |entry| entries << entry.dn }

    assert result.success?
    assert_equal ["uid=one,ou=People"], entries
    assert_equal 2, @socket.written.size
    continuation = @socket.written[1].read_ber(Net::LDAP::AsnSyntax)
    assert_equal operation.message_id, continuation[0]
    assert_equal Net::LDAP::PDU::SearchRequest,
                 continuation[1].ber_identifier & 0x1f
  end

  def test_referrals_are_ignored_unless_requested
    search = @connection.start_search(search_args)
    @responses << referral_pdu(search.message_id, ["ldap://other"])
    @responses << result_pdu(search.message_id, Net::LDAP::PDU::SearchResult)

    result = search.wait
    assert result.success?
    assert_empty search.drain_entries
  end
end

class TestLDAPOperationFacade < Test::Unit::TestCase
  class FakeConcurrentConnection
    attr_reader :started

    def start_search(args, &block)
      @started ||= []
      @started << [:search, args, block]
      :search_operation
    end

    def start_compare(args)
      @started ||= []
      @started << [:compare, args]
      :compare_operation
    end

    def compare(args)
      OpenStruct.new(success?: true)
    end
  end

  def test_start_search_requires_open_connection
    ldap = Net::LDAP.new
    assert_raise Net::LDAP::ConnectionNotOpenError do
      ldap.start_search(base: "dc=example,dc=org")
    end
  end

  def test_start_compare_requires_open_connection
    ldap = Net::LDAP.new
    assert_raise Net::LDAP::ConnectionNotOpenError do
      ldap.start_compare(dn: "uid=user1", attribute: "uid", value: "user1")
    end
  end

  def test_start_search_uses_open_connection
    ldap = Net::LDAP.new
    ldap.connection = FakeConcurrentConnection.new
    result = ldap.start_search(base: "dc=example,dc=org",
                               ignore_server_caps: true)
    assert_equal :search_operation, result
  end

  def test_compare_requires_open_connection
    ldap = Net::LDAP.new
    assert_raise Net::LDAP::ConnectionNotOpenError do
      ldap.start_compare(dn: "uid=user1", attribute: "uid", value: "user1")
    end
  end

  def test_blocking_compare_returns_boolean
    ldap = Net::LDAP.new
    ldap.connection = FakeConcurrentConnection.new
    assert ldap.compare(dn: "uid=user1", attribute: "uid", value: "user1")
  end
end
