# -*- ruby encoding: utf-8 -*-

# An Net::LDAP::Operation tracks a single LDAP protocol request (and its
# message ID) independently of the code that issued it. It is the handle
# returned by the concurrent operation interface (Net::LDAP#start_search,
# Net::LDAP#start_compare and friends).
#
# Several operations may be outstanding on one connection at the same
# time. Every response PDU is attributed to the operation whose message ID
# it carries, so a long-running search never blocks a short compare on the
# same connection.
#
# An operation is finished once a terminal result has been received (or the
# connection has gone away). Operations are never re-used: a fresh message
# ID is allocated for every request, so late entries arriving for a
# finished operation can never be delivered to an operation that happened
# to reuse its number.
class Net::LDAP::Operation
  # The message ID used for the request. This is the ID that appears in
  # every PDU related to the operation.
  attr_reader :message_id
  alias_method :msg_id, :message_id

  # :call-seq:
  #   operation.kind -> symbol
  #
  # The kind of operation, one of +:search+, +:compare+, +:cancel+ or any
  # other operation name supported by the concurrent interface.
  attr_reader :kind

  # :call-seq:
  #   operation.entry_count -> integer
  #
  # Number of entries (excluding referrals) received for the operation so
  # far, including entries already drained with #drain_entries.
  attr_reader :entry_count

  # :call-seq:
  #   operation.result_code -> integer or nil
  #
  # The result code of the terminal result PDU, or nil until the operation
  # has finished. See Net::LDAP::ResultCode*.
  attr_reader :result_code

  def initialize(connection, message_id, kind, return_referrals: false,
                 &on_entry) #:nodoc:
    @connection = connection
    @message_id = message_id
    @kind = kind
    @on_entry = on_entry
    @return_referrals = return_referrals

    @entries = []
    @result_pdu = nil
    @mutex = Mutex.new
    @entry_count = 0

    # Callback supplied by the connection for operations that need to send
    # a continuation request (RFC 2696 paged searches). Receives this
    # operation and the result PDU that carries the paging cookie.
    @continue = nil
  end

  # :call-seq:
  #   operation.finished? -> true or false
  #
  # Returns true once the operation has a terminal result, whether from
  # the server, from an RFC 3909 cancellation, or because the connection
  # was closed.
  def finished?
    @mutex.synchronize { !@result_pdu.nil? }
  end

  # :call-seq:
  #   operation.cancelled? -> true or false
  #
  # Returns true if the operation ended because it was cancelled with
  # RFC 3909 (result code
  # Net::LDAP::ResultCodeCanceled).
  def cancelled?
    result_code == Net::LDAP::ResultCodeCanceled
  end

  # :call-seq:
  #   operation.success? -> true or false
  #
  # Returns true once the operation has finished with a non-error result
  # code. Until the operation finishes this returns false.
  def success?
    pdu = @mutex.synchronize { @result_pdu }
    pdu ? pdu.success? : false
  end

  # :call-seq:
  #   operation.failure? -> true or false
  def failure?
    !success?
  end

  # :call-seq:
  #   operation.result -> Net::LDAP::PDU or nil
  #
  # The terminal result PDU for the operation, or nil if it has not
  # finished yet. The PDU carries +result_code+, +error_message+ and
  # +matched_dn+ (and controls, for searches).
  def result
    @mutex.synchronize { @result_pdu }
  end

  # :call-seq:
  #   operation.wait -> Net::LDAP::PDU
  #
  # Blocks until the operation has a terminal result and returns that
  # PDU. Other outstanding operations are still serviced while this one is
  # waited on: responses carrying other message IDs are read from the
  # socket and delivered to their own operations rather than being held up.
  #
  # If the connection closes before a result arrives, each unfinished
  # operation independently receives a synthesized terminal result with a
  # non-success result code.
  #
  # This is cooperative: waiting pumps PDUs off the connection on the
  # calling thread. Responses belonging to other operations are still
  # dispatched to those operations while this one is pending.
  def wait
    loop do
      pdu = result
      return pdu if pdu
      # nil means end-of-stream: finalize_pending_operations terminated
      # this operation and #result will be set on the next iteration.
      @connection.pump
    end
  end

  # :call-seq:
  #   operation.entries { |entry| ... } -> Net::LDAP::PDU
  #   operation.each_entry { |entry| ... } -> Net::LDAP::PDU
  #
  # Streams search entries to the given block as they arrive (pumping the
  # connection as needed) and returns the terminal result PDU when the
  # search finishes.
  #
  # Entries belonging to other operations are dispatched to those
  # operations; they are not yielded here. Only entries received for this
  # operation's message ID are yielded.
  def entries
    raise ArgumentError, "a block is required" unless block_given?
    loop do
      entry = @mutex.synchronize { @entries.shift }
      if entry
        yield entry
        next
      end
      return result if finished?
      @connection.pump
    end
  end
  alias_method :each_entry, :entries

  # :call-seq:
  #   operation.drain_entries -> array of Net::LDAP::Entry
  #
  # Non-blocking: returns the entries received so far and removes them
  # from the operation's queue. Does not read from the socket. Combine with
  # #wait or Net::LDAP::Connection#pump to make progress.
  def drain_entries
    @mutex.synchronize do
      entries = @entries
      @entries = []
      entries
    end
  end

  # :call-seq:
  #   operation.cancel -> Net::LDAP::Operation
  #
  # Sends an RFC 3909 Cancel request for this operation and returns a
  # separate Operation tracking the *cancel* request itself. Call #wait on
  # it to obtain the cancel request's result. The original operation
  # terminates independently with its own terminal result (typically
  # Net::LDAP::ResultCodeCanceled); retrieve that with this operation's
  # #wait or #result.
  #
  # Raises Net::LDAP::Error if the operation has already finished, or if
  # the connection is closed.
  def cancel
    raise Net::LDAP::Error, "operation #{@message_id} is already finished" if finished?
    @connection.cancel_operation(self)
  end

  # :nodoc: internal: called by the connection when a PDU is routed here.
  #
  # Returns +:continue+ if the PDU was consumed by sending a continuation
  # request (paged search), +:finished+ if the operation is now complete,
  # or +:entry+ if an intermediate entry was delivered.
  def deliver(pdu)
    case @kind
    when :search
      deliver_search(pdu)
    else
      finish(pdu)
      :finished
    end
  end

  # :nodoc: internal: terminate the operation with a synthesized PDU, e.g.
  # when the connection is closed. Does nothing if it already finished.
  def close_with(pdu)
    finish(pdu)
    nil
  end

  # :nodoc: internal: continuation callback used for paged searches.
  def continue=(callback)
    @continue = callback
  end

  private

  def deliver_search(pdu)
    case pdu.app_tag
    when Net::LDAP::PDU::SearchReturnedData
      @mutex.synchronize { @entry_count += 1 }
      receive_entry(pdu.search_entry)
      :entry
    when Net::LDAP::PDU::SearchResultReferral
      receive_entry(referral_entry(pdu.search_referrals)) if @return_referrals && pdu.search_referrals
      :entry
    when Net::LDAP::PDU::SearchResult
      if @return_referrals && pdu.result_code == Net::LDAP::ResultCodeReferral
        receive_entry(referral_entry(pdu.search_referrals))
      end
      if @continue && pdu.result_code == Net::LDAP::ResultCodeSuccess &&
         more_pages?(pdu)
        @continue.call(self, pdu)
        :continue
      else
        finish(pdu)
        :finished
      end
    else
      raise Net::LDAP::ResponseTypeInvalidError,
            "invalid response-type in search: #{pdu.app_tag}"
    end
  end

  def more_pages?(pdu)
    controls = pdu.result_controls
    return false unless controls
    controls.any? do |control|
      next false unless control.oid == Net::LDAP::LDAPControls::PAGED_RESULTS
      next false if control.value.nil? || control.value.empty?
      cookie = control.value.read_ber[1]
      !cookie.nil? && !cookie.empty?
    end
  end

  def referral_entry(referrals)
    entry = Net::LDAP::Entry.new
    entry[:search_referrals] = referrals || []
    entry
  end

  def receive_entry(entry)
    @mutex.synchronize { @entries << entry }
    @on_entry&.call(entry)
  end

  def finish(pdu)
    @mutex.synchronize do
      return if @result_pdu
      @result_pdu = pdu
      @result_code = pdu.result_code
    end
  end
end
