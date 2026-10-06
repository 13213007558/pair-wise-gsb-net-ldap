# -*- ruby encoding: utf-8 -*-
require 'thread'

##
# An in-progress LDAP operation on a Net::LDAP connection.
#
# Every request sent to the server gets its own Operation object, keyed by
# its LDAP message ID. Multiple operations may be outstanding at the same
# time; responses are always delivered to the operation whose message ID
# appears in the reply.
#
# An Operation is created by one of the concurrent request methods:
# Net::LDAP#search_operation, Net::LDAP#compare_operation, or
# Net::LDAP::Connection#begin_search / #begin_compare.
#
#   op = ldap.search_operation(base: "dc=example,dc=org",
#                              filter: "(cn=George Washington)")
#
#   op.each_entry do |entry|   # stream search entries as they arrive
#     process(entry)
#   end
#
#   result = op.result         # block until the terminal result arrives
#
# An operation that is no longer needed can be abandoned using #cancel,
# which implements RFC 3909 Cancel.
class Net::LDAP::Operation
  # Internal: the request is still on the wire.
  ACTIVE   = :active
  # Internal: the server sent a terminal result.
  COMPLETE = :complete
  # Internal: the operation was canceled (RFC 3909).
  CANCELED = :canceled
  # Internal: the connection was closed before a terminal result arrived.
  CLOSED   = :closed

  ENTRY_SENTINEL = :__net_ldap_entry_sentinel__
  private_constant :ENTRY_SENTINEL

  ##
  # A terminal result synthesized by the client rather than received from
  # the server (currently: the result handed to an operation whose
  # connection closed before the server replied). It exposes the same
  # surface as the result of a Net::LDAP::PDU.
  class TerminalResult
    attr_reader :result_code, :error_message, :matched_dn, :message, :app_tag

    def initialize(result_code, error_message, app_tag = nil)
      @result_code = result_code
      @error_message = error_message
      @matched_dn = ""
      @message = Net::LDAP.result2string(result_code)
      @app_tag = app_tag
    end

    def result
      {
        :resultCode => @result_code,
        :matchedDN => @matched_dn,
        :errorMessage => @error_message,
      }
    end

    def status
      Net::LDAP::ResultCodesNonError.include?(@result_code) ? :success : :failure
    end

    def success?
      status == :success
    end

    def failure?
      !success?
    end

    def connection_closed?
      @result_code == Net::LDAP::ResultCodeConnectionClosed
    end
  end

  ##
  # The LDAP message ID used by this operation. It is the value that appears
  # in every request and response belonging to the operation.
  attr_reader :message_id

  ##
  # Number of search entries delivered to this operation so far.
  attr_reader :entry_count

  # Internal: Create an operation.
  #
  # - connection: the Net::LDAP::Connection that owns the operation
  # - message_id: the integer LDAP message ID
  # - type:       a Symbol naming the request kind (:search, :compare, ...)
  def initialize(connection, message_id, type)
    @connection = connection
    @message_id = message_id
    @type = type

    @mutex = Mutex.new

    @state = ACTIVE
    @result = nil

    # Entry queue. Search entries and referrals are pushed here as the
    # server streams them. ENTRY_SENTINEL marks the end of the stream.
    @entries = Queue.new

    @entry_count = 0

    # Internal: invoked by the connection with the terminal SearchResult
    # PDU of a paged search so the next page can be requested
    # transparently. Returns true when another page was requested.
    @continuation = nil

    # Internal: Net::LDAP::Operation representing the RFC 3909 Cancel
    # request used to abandon this operation, if #cancel was called.
    @cancel_operation = nil
  end

  ##
  # The request kind, one of +:search+, +:compare+, +:cancel+, ...
  def type
    @type
  end

  ##
  # Returns true while no terminal result has been received.
  def active?
    @mutex.synchronize { @state == ACTIVE }
  end

  ##
  # Returns true when a terminal result has been delivered (including
  # cancellation and connection close).
  def finished?
    @mutex.synchronize { @state != ACTIVE }
  end

  ##
  # Returns true when the operation was terminated by an RFC 3909 Cancel
  # request (either confirmed by the server or overtaken by the server's
  # terminal result).
  def canceled?
    @mutex.synchronize { @state == CANCELED }
  end

  ##
  # Returns true when the operation ended because the connection was
  # closed before the server sent a terminal result.
  def connection_closed?
    @mutex.synchronize { @state == CLOSED }
  end

  ##
  # Yields each search entry as it is received from the server. Search
  # result referrals are also yielded as Net::LDAP::Entry objects when the
  # request asked for +:return_referrals+.
  #
  # Reads are driven cooperatively: while an entry is not yet available and
  # the operation is still active, the calling thread reads and dispatches
  # PDU responses from the single BER reader, so a long-running search
  # cannot starve shorter operations sharing the connection.
  #
  # After the terminal result is received, any entries still buffered for
  # the operation are yielded before the method returns.
  def each_entry
    return to_enum(:each_entry) unless block_given?

    loop do
      entry = @connection.drain_for(self) { pop_entry }
      break if entry.equal?(ENTRY_SENTINEL)
      yield entry
    end
    self
  end

  ##
  # Returns the next search entry, or nil when the entry stream is
  # exhausted. Drives the BER reader like #each_entry while waiting.
  def next_entry
    entry = @connection.drain_for(self) { pop_entry }
    return nil if entry.equal?(ENTRY_SENTINEL)
    entry
  end

  ##
  # Waits for and returns every entry for the operation as an Array. The
  # operation's terminal result is still available from #result afterwards.
  def to_a
    entries = []
    each_entry { |entry| entries << entry }
    entries
  end

  ##
  # Blocks until the terminal result PDU for the operation arrives and
  # returns it. While waiting, the calling thread cooperatively reads and
  # dispatches responses from the connection's single BER reader, which
  # lets other operations sharing the connection (short compares, other
  # searches) complete first.
  #
  # +timeout+ (optional, in seconds) bounds the wait; a
  # Net::LDAP::OperationTimeoutError is raised if it elapses.
  #
  # The result behaves like a Net::LDAP::PDU (it responds to
  # #result_code, #error_message, #success?, ...). When the connection was
  # closed before a result arrived, #result_code is
  # Net::LDAP::ResultCodeConnectionClosed.
  def result(timeout = nil)
    @wait_deadline = timeout ? current_time + timeout : nil
    @connection.drain_for(self) do
      result = nil
      timed_out = false
      @mutex.synchronize do
        if @state != ACTIVE
          result = @result
        else
          remaining = @wait_deadline ? @wait_deadline - current_time : nil
          if remaining && remaining <= 0
            timed_out = true
          end
        end
      end
      raise Net::LDAP::OperationTimeoutError,
            "operation #{@message_id} did not complete within #{timeout} seconds" if timed_out
      result
    end
  end
  alias_method :wait, :result

  # Internal: Absolute monotonic deadline for the current #result wait, if
  # a timeout was given. Used by Connection#drain_for to bound blocking
  # socket reads.
  def wait_deadline
    @mutex.synchronize { @wait_deadline }
  end

  ##
  # Cancels the outstanding operation using RFC 3909 Cancel.
  #
  # Returns the Operation representing the cancel request itself. The
  # cancel request has its own message ID and its result is tracked
  # independently from the canceled operation's termination result:
  #
  #   search = ldap.search_operation(...)
  # cancel = search.cancel
  # cancel.result.result_code      # Success / NoSuchOperation / CannotCancel
  # search.result.result_code      # Canceled (or the server's own result)
  #
  # Calling #cancel on an operation that has already finished returns the
  # existing cancel operation (nil if the operation finished before any
  # cancel was sent) without sending anything.
  def cancel
    @mutex.synchronize do
      return @cancel_operation if @cancel_operation
      return nil unless @state == ACTIVE
      @cancel_operation = @connection.cancel_operation(self)
    end
  end

  # Internal: the operation created by #cancel, if any.
  def cancel_operation
    @mutex.synchronize { @cancel_operation }
  end

  # Internal: Receive a PDU routed to this operation by the connection.
  #
  # Late entries belonging to an operation that has already terminated are
  # silently dropped; message IDs are never reused on a connection, so a
  # late entry can never be handed to a different operation.
  #
  # Returns true when the PDU terminated the operation.
  def deliver(pdu)
    @mutex.synchronize do
      return false unless @state == ACTIVE
      return false unless pdu.message_id == @message_id

      case pdu.app_tag
      when Net::LDAP::PDU::SearchReturnedData
        @entry_count += 1
        @entries << pdu.search_entry
        false
      when Net::LDAP::PDU::SearchResultReferral
        deliver_referral(pdu)
        false
      else
        # A terminal result for a search may be an intermediate page whose
        # continuation requests the next page on the same message ID. Only
        # finish the operation when no continuation is driven.
        unless continue_pages(pdu)
          state = pdu.result_code == Net::LDAP::ResultCodeCanceled ? CANCELED : COMPLETE
          finish(state, pdu)
        end
        true
      end
    end
  end

  # Internal: Force the operation to a terminal state without a server
  # result. Used when the connection is closed while the operation is still
  # outstanding. Every unfinished operation gets its own synthetic result.
  def finish_without_result(state, result_pdu)
    @mutex.synchronize do
      return unless @state == ACTIVE
      finish(state, result_pdu)
    end
  end

  # Internal: Register the paged-search continuation used by #deliver.
  def continuation=(callable)
    @mutex.synchronize { @continuation = callable }
  end

  # Internal: Pop one buffered entry without touching the BER reader. The
  # block form is executed by Connection#drain_for.
  def pop_entry
    begin
      @entries.pop(true)
    rescue ThreadError
      nil
    end
  end

  # Internal: Whether an entry (or sentinel) is already buffered.
  def entry_available?
    !@entries.empty?
  end

  # Internal: Buffer a referral as an Entry when the caller asked for them.
  def deliver_referral(pdu)
    @entries << referral_entry(pdu)
  end

  # Internal: Request the next page of a paged search. Returns true when
  # the PDU was consumed as a page boundary rather than a terminal result.
  def continue_pages(pdu)
    return false unless @continuation
    return false unless @continuation.call(pdu)
    true
  end

  # Internal: Move to a terminal state and wake anyone waiting. Callers must
  # hold @mutex.
  def finish(state, result_pdu)
    @state = state
    @result = result_pdu
    @entries << ENTRY_SENTINEL
    @continuation = nil
  end

  def referral_entry(pdu)
    entry = Net::LDAP::Entry.new
    entry[:search_referrals] = (pdu.search_referrals || [])
    entry
  end

  if defined?(Process::CLOCK_MONOTONIC)
    def current_time
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  else
    def current_time
      Time.now.to_f
    end
  end
end
