# This is a private class used internally by the library. It should not
# be called by user code.
class Net::LDAP::Connection #:nodoc:
  include Net::LDAP::Instrumentation

  # Seconds before failing for socket connect timeout
  DefaultConnectTimeout = 5

  LdapVersion = 3

  # Initialize a connection to an LDAP server
  #
  # :server
  #   :hosts   Array of tuples specifying host, port
  #   :host    host
  #   :port    port
  #   :socket  prepared socket
  #
  def initialize(server = {})
    @server = server
    @instrumentation_service = server[:instrumentation_service]

    # Allows tests to parameterize what socket class to use
    @socket_class = server.fetch(:socket_class, DefaultSocket)

    # Outstanding operations keyed by message ID. Replies read from the
    # socket are routed back to the operation that sent the request.
    @operations = {}
    # Inboxes for the internal blocking (non-concurrent) call paths such as
    # bind, modify and start_tls. Each is a Queue fed by #route_pdu. A
    # reply whose ID has no active reader is buffered under a fresh inbox
    # rather than dropped, preserving the historical queueing behavior.
    @inboxes = Hash.new { |hash, key| hash[key] = Queue.new }
    # Unsolicited notifications carry message ID 0 and never belong to a
    # request; they are collected here and via the registered callback.
    @unsolicited = Queue.new
    @unsolicited_callback = nil
    @unsolicited_mutex = Mutex.new
    # Serializes BER fragment reads. There is exactly one place in the
    # library that reads PDU bytes from the socket (#read).
    @read_mutex = Mutex.new
    # Serializes request writes so concurrent operations can't interleave
    # BER bytes.
    @write_mutex = Mutex.new
    # Guards the operation/inbox registries.
    @registry_mutex = Mutex.new
    @closing = false

    yield self if block_given?
  end

  def socket_class=(socket_class)
    @socket_class = socket_class
  end

  def prepare_socket(server, timeout=nil, hostname='127.0.0.1')
    socket = server[:socket]
    encryption = server[:encryption]

    @conn = socket
    setup_encryption(encryption, timeout, hostname) if encryption
  end

  def open_connection(server)
    hosts = server[:hosts]
    encryption = server[:encryption]

    timeout = server[:connect_timeout] || DefaultConnectTimeout
    socket_opts = {
      connect_timeout: timeout,
    }

    errors = []
    hosts.each do |host, port|
      begin
        prepare_socket(server.merge(socket: @socket_class.new(host, port, socket_opts)), timeout, host)
        if encryption
          if encryption[:tls_options] &&
             encryption[:tls_options][:verify_mode] &&
             encryption[:tls_options][:verify_mode] == OpenSSL::SSL::VERIFY_NONE
            warn "not verifying SSL hostname of LDAPS server '#{host}:#{port}'"
          else
            @conn.post_connection_check(host)
          end
        end
        return
      rescue Net::LDAP::Error, SocketError, SystemCallError,
             OpenSSL::SSL::SSLError => e
        # Ensure the connection is closed in the event a setup failure.
        close
        errors << [e, host, port]
      end
    end

    raise Net::LDAP::ConnectionError.new(errors)
  end

  module GetbyteForSSLSocket
    def getbyte
      c = getc
      c && c.ord
    end
  end

  module FixSSLSocketSyncClose
    def close
      super
      io.close
    end
  end

  def self.wrap_with_ssl(io, tls_options = {}, timeout=nil, hostname=nil)
    raise Net::LDAP::NoOpenSSLError, "OpenSSL is unavailable" unless Net::LDAP::HasOpenSSL

    ctx = OpenSSL::SSL::SSLContext.new

    # By default, we do not verify certificates. For a 1.0 release, this should probably be changed at some point.
    # See discussion in https://github.com/ruby-ldap/ruby-net-ldap/pull/161
    ctx.set_params(tls_options) unless tls_options.empty?

    conn = OpenSSL::SSL::SSLSocket.new(io, ctx)
    conn.hostname = hostname

    begin
      if timeout
        conn.connect_nonblock
      else
        conn.connect
      end
    rescue IO::WaitReadable
      raise Errno::ETIMEDOUT, "OpenSSL connection read timeout" unless
        IO.select([conn], nil, nil, timeout)
      retry
    rescue IO::WaitWritable
      raise Errno::ETIMEDOUT, "OpenSSL connection write timeout" unless
        IO.select(nil, [conn], nil, timeout)
      retry
    end

    # Doesn't work:
    # conn.sync_close = true

    conn.extend(GetbyteForSSLSocket) unless conn.respond_to?(:getbyte)
    conn.extend(FixSSLSocketSyncClose)

    conn
  end

  #--
  # Helper method called only from prepare_socket or open_connection, and only
  # after we have a successfully-opened @conn instance variable, which is a TCP
  # connection.  Depending on the received arguments, we establish SSL,
  # potentially replacing the value of @conn accordingly. Don't generate any
  # errors here if no encryption is requested. DO raise Net::LDAP::Error objects
  # if encryption is requested and we have trouble setting it up. That includes
  # if OpenSSL is not set up on the machine. (Question: how does the Ruby
  # OpenSSL wrapper react in that case?) DO NOT filter exceptions raised by the
  # OpenSSL library. Let them pass back to the user. That should make it easier
  # for us to debug the problem reports. Presumably (hopefully?) that will also
  # produce recognizable errors if someone tries to use this on a machine
  # without OpenSSL.
  #
  # The simple_tls method is intended as the simplest, stupidest, easiest
  # solution for people who want nothing more than encrypted comms with the
  # LDAP server. It doesn't do any server-cert validation and requires
  # nothing in the way of key files and root-cert files, etc etc. OBSERVE:
  # WE REPLACE the value of @conn, which is presumed to be a connected
  # TCPSocket object.
  #
  # The start_tls method is supported by many servers over the standard LDAP
  # port. It does not require an alternative port for encrypted
  # communications, as with simple_tls. Thanks for Kouhei Sutou for
  # generously contributing the :start_tls path.
  #++
  def setup_encryption(args, timeout=nil, hostname=nil)
    args[:tls_options] ||= {}
    case args[:method]
    when :simple_tls
      @conn = self.class.wrap_with_ssl(@conn, args[:tls_options], timeout, hostname)
      # additional branches requiring server validation and peer certs, etc.
      # go here.
    when :start_tls
      message_id = next_msgid
      request    = [
        Net::LDAP::StartTlsOid.to_ber_contextspecific(0),
      ].to_ber_appsequence(Net::LDAP::PDU::ExtendedRequest)

      write(request, nil, message_id)
      pdu = queued_read(message_id)

      if pdu.nil? || pdu.app_tag != Net::LDAP::PDU::ExtendedResponse
        raise Net::LDAP::NoStartTLSResultError, "no start_tls result"
      end

      raise Net::LDAP::StartTLSError,
            "start_tls failed: #{pdu.result_code}" unless pdu.result_code.zero?
      @conn = self.class.wrap_with_ssl(@conn, args[:tls_options], timeout, hostname)
    else
      raise Net::LDAP::EncMethodUnsupportedError, "unsupported encryption method #{args[:method]}"
    end
  end

  #--
  # This is provided as a convenience method to make sure a connection
  # object gets closed without waiting for a GC to happen. Clients shouldn't
  # have to call it, but perhaps it will come in handy someday.
  #++
  def close
    conn = nil
    @write_mutex.synchronize do
      if !defined?(@conn) || @conn.nil?
        @closing = true
        finalize_operations
        return
      end
      conn = @conn
      @conn = nil
      @closing = true
    end

    conn.close

    # Give a cooperative reader mid-flight a chance to observe the close
    # instead of raising on the dead socket; then give every outstanding
    # operation its own terminal result regardless.
    @read_mutex.synchronize { nil }
    finalize_operations
  end

  # Internal: Register an inbox for a blocking request before it is written,
  # so a reply that arrives before the subsequent #queued_read cannot be
  # misrouted. Returns the Queue to read from.
  def register_inbox(message_id)
    @registry_mutex.synchronize do
      @inboxes[message_id] = Queue.new unless @inboxes.key?(message_id)
      @inboxes[message_id]
    end
  end

  # Internal: Blocking read used by the synchronous request paths (bind,
  # modify, add, delete, rename, start_tls, password_modify, whoami and the
  # blocking search loop). While waiting it cooperatively drives the single
  # BER reader, so replies belonging to concurrent operations are routed to
  # them instead of being held hostage by this call.
  #
  # Returns a Net::LDAP::PDU object, or nil when the connection closes.
  def queued_read(message_id)
    register_inbox(message_id)
    if pdu = pop_inbox(message_id)
      return pdu
    end

    drain do
      if pdu = pop_inbox(message_id)
        pdu
      else
        raw = read
        next nil unless raw

        parsed = raw.is_a?(Net::LDAP::PDU) ? raw : parse_pdu(raw)
        if parsed.message_id == message_id
          parsed
        else
          route_pdu(parsed)
          nil
        end
      end
    end
  end

  # Internal: Non-blocking inbox poll. Returns nil when no PDU is buffered.
  def pop_inbox(message_id)
    inbox = @registry_mutex.synchronize { @inboxes[message_id] }
    return nil unless inbox
    begin
      inbox.pop(true)
    rescue ThreadError
      nil
    end
  end
  private :pop_inbox

  # Internal: Compatibility accessor for tests and older call paths. Maps a
  # message ID to its blocking inbox Queue.
  def message_queue
    @registry_mutex.synchronize { @inboxes }
  end

  ##
  # Register a block invoked (on the reader-driving thread) whenever the
  # server sends an unsolicited notification (message ID 0). Such messages
  # never correspond to a request and are never delivered to an operation.
  #
  # The block also receives every notification already buffered before
  # registration.
  def on_unsolicited_notification(callback = nil, &block)
    callback ||= block
    @unsolicited_mutex.synchronize do
      @unsolicited_callback = callback
      until @unsolicited.empty?
        begin
          pdu = @unsolicited.pop(true)
        rescue ThreadError
          break
        end
        callback.call(pdu) if callback
      end
    end
  end

  ##
  # Returns the Queue of unsolicited notifications (message ID 0) received
  # on the connection.
  def unsolicited_notifications
    @unsolicited
  end

  # Internal: Drive BER reads while +block+ cannot yet produce a value.
  #
  # This is the cooperative multiplexing loop: the calling block polls its
  # own mailbox; when it finds nothing it reads exactly one whole PDU from
  # the socket and routes it (potentially completing a *different* operation
  # that shares this connection), then retries its own mailbox.
  #
  # Returns whatever the block returns once it is non-nil. Returns nil if
  # the connection closes with nothing available.
  def drain(read_timeout = nil)
    loop do
      value = yield
      return value if value

      pdu = read_with_timeout(read_timeout)
      if pdu
        route_pdu(pdu)
      else
        # End of stream: finalize every outstanding operation with its own
        # connection-closed terminal result, then stop this reader.
        @closing = true
        finalize_operations
        return nil
      end
    end
  end

  # Internal: Cooperative read loop for a specific operation. +block+ is the
  # operation-local wait (waiting for an entry or the terminal result) and
  # returns nil while the operation still needs to wait.
  def drain_for(operation)
    deadline = operation.wait_deadline
    loop do
      value = yield
      return value if value

      remaining = deadline ? deadline - current_time : nil
      if remaining && remaining <= 0
        next # let the operation raise its OperationTimeoutError
      end

      pdu = read_with_timeout(remaining)
      if pdu
        if pdu == :read_timeout
          next
        else
          route_pdu(pdu)
        end
      else
        # A nil from a bounded read is either a wait timeout (keep
        # looping so the operation can raise OperationTimeoutError) or a
        # real end-of-stream (finalize outstanding operations).
        remaining = deadline ? deadline - current_time : nil
        if remaining && remaining > 0 && !@closing
          next
        end
        @closing = true
        finalize_operations
        return nil
      end
    end
  end

  # Internal: Monotonic clock used by the cooperative reader.
  if defined?(Process::CLOCK_MONOTONIC)
    def current_time
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  else
    def current_time
      Time.now.to_f
    end
  end
  private :current_time

  # Internal: Read one PDU, bounded by +timeout+ seconds when given. Uses
  # IO.select so a blocking operation wait can time out instead of being
  # stuck in a blocking socket read forever. Returns :read_timeout when the
  # wait elapses with no data, nil on clean end-of-stream, or a PDU.
  def read_with_timeout(timeout)
    return read if timeout.nil?
    return :read_timeout if timeout <= 0

    io = socket
    # Even bounded reads funnel through the single BER reader mutex so
    # concurrent waiters can never reassemble interleaved fragments.
    @read_mutex.synchronize do
      if io.respond_to?(:read_ber_with_timeout)
        ber = io.read_ber_with_timeout(Net::LDAP::AsnSyntax, timeout)
        return ber if ber.nil? || ber == :read_timeout
        instrument "parse_pdu.net_ldap_connection" do |payload|
          payload[:pdu] = Net::LDAP::PDU.new(ber)
        end
      else
        select_io = io.respond_to?(:reader_io) ? io.reader_io : io
        return :read_timeout unless IO.select([select_io], nil, nil, timeout)
        ber = io.read_ber(Net::LDAP::AsnSyntax)
        return nil unless ber
        parse_pdu(ber)
      end
    end
  end
  private :read_with_timeout

  # Internal: Route one parsed PDU to its owner by message ID.
  #
  # Message ID 0 is an unsolicited notification and is never attributed to
  # a request. PDUs for operations that have already terminated are dropped,
  # and because message IDs are never reused on a connection a late entry
  # cannot be handed to a new operation.
  def route_pdu(pdu)
    pdu = parse_pdu(pdu) unless pdu.is_a?(Net::LDAP::PDU)

    if pdu.message_id.zero?
      deliver_unsolicited(pdu)
      return
    end

    target = nil
    inbox = nil
    @registry_mutex.synchronize do
      target = @operations[pdu.message_id]
      inbox = @inboxes[pdu.message_id]
    end

    if target
      target.deliver(pdu)
    elsif inbox
      inbox << pdu
    else
      instrument "unrouted_message.net_ldap_connection",
                 message_id: pdu.message_id, pdu: pdu
    end
  end

  # Internal: Deliver an unsolicited notification (message ID 0).
  def deliver_unsolicited(pdu)
    @unsolicited_mutex.synchronize do
      @unsolicited << pdu
      @unsolicited_callback.call(pdu) if @unsolicited_callback
    end
  end

  # Internal: Synthesize a terminal result for an operation cut off by the
  # connection closing. Responds to the same surface as Net::LDAP::PDU.
  def closed_result
    Net::LDAP::Operation::TerminalResult.new(
      Net::LDAP::ResultCodeConnectionClosed, "connection closed"
    )
  end

  # Internal: Give every outstanding operation and blocking inbox its own
  # terminal state when the connection has gone away.
  def finalize_operations
    operations = nil
    inbox_list = nil
    @registry_mutex.synchronize do
      operations = @operations.values
      inbox_list = @inboxes.values.uniq
    end

    result = closed_result
    operations.each do |operation|
      operation.finish_without_result(Net::LDAP::Operation::CLOSED, result)
    end
    inbox_list.each { |inbox| inbox << result unless inbox.closed? }
  end

  # Internal: Reads and parses data from the configured connection.
  #
  # - syntax: the BER syntax to use to parse the read data with
  #
  # Returns parsed Net::LDAP::PDU object.
  def read(syntax = Net::LDAP::AsnSyntax)
    # All BER fragment reads funnel through this method and this mutex, so
    # even when many operations are driven concurrently only one reader at a
    # time can pull bytes from (or reassemble a PDU out of) the stream.
    @read_mutex.synchronize do
      ber_object =
        instrument "read.net_ldap_connection", :syntax => syntax do |payload|
          socket.read_ber(syntax) do |id, content_length|
            payload[:object_type_id] = id
            payload[:content_length] = content_length
          end
        end
      return unless ber_object

      parse_pdu(ber_object)
    end
  rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
    # The socket vanished (typically because #close was called from another
    # thread). Treat it as end-of-stream so outstanding operations can be
    # finalized instead of crashing the reader-driving call.
    raise unless @closing
    nil
  end
  private :read

  # Internal: Parse a raw BER object into a Net::LDAP::PDU.
  def parse_pdu(ber_object)
    instrument "parse_pdu.net_ldap_connection" do |payload|
      pdu = payload[:pdu]  = Net::LDAP::PDU.new(ber_object)

      payload[:message_id] = pdu.message_id
      payload[:app_tag]    = pdu.app_tag

      pdu
    end
  end
  private :parse_pdu

  # Internal: Write a BER formatted packet with the next message id to the
  # configured connection.
  #
  # - request: required BER formatted request
  # - controls: optional BER formatted controls
  #
  # Returns the return value from writing to the connection, which in some
  # cases is the Integer number of bytes written to the socket.
  def write(request, controls = nil, message_id = next_msgid)
    @write_mutex.synchronize do
      if @closing
        raise Net::LDAP::ConnectionClosedError, "cannot write; the connection is closed"
      end

      instrument "write.net_ldap_connection" do |payload|
        packet = [message_id.to_ber, request, controls].compact.to_ber_sequence
        payload[:content_length] = socket.write(packet)
      end
    end
  end
  private :write

  def next_msgid
    # Message IDs are allocated monotonically and are *never* reused on a
    # connection, so a late entry for a finished operation can never be
    # delivered to a new operation that happens to reuse the same number.
    @registry_mutex.synchronize do
      @msgid ||= 0
      @msgid += 1
    end
  end

  # Internal: Allocate a message ID, register a new Operation and return it.
  # Called before the request is written.
  def register_operation(type)
    message_id = next_msgid
    operation = Net::LDAP::Operation.new(self, message_id, type)
    @registry_mutex.synchronize { @operations[message_id] = operation }
    operation
  end

  def bind(auth)
    instrument "bind.net_ldap_connection" do |payload|
      payload[:method] = meth = auth[:method]
      adapter = Net::LDAP::AuthAdapter[meth]
      adapter.new(self).bind(auth)
    end
  end

  #--
  # Allow the caller to specify a sort control
  #
  # The format of the sort control needs to be:
  #
  # :sort_control => ["cn"]  # just a string
  # or
  # :sort_control => [["cn", "matchingRule", true]] #attribute, matchingRule, direction (true / false)
  # or
  # :sort_control => ["givenname","sn"] #multiple strings or arrays
  #
  def encode_sort_controls(sort_definitions)
    return sort_definitions unless sort_definitions

    sort_control_values = sort_definitions.map do |control|
      control = Array(control) # if there is only an attribute name as a string then infer the orderinrule and reverseorder
      control[0] = String(control[0]).to_ber,
      control[1] = String(control[1]).to_ber,
      control[2] = (control[2] == true).to_ber
      control.to_ber_sequence
    end
    [
      Net::LDAP::LDAPControls::SORT_REQUEST.to_ber,
      false.to_ber,
      sort_control_values.to_ber_sequence.to_s.to_ber,
    ].to_ber_sequence
  end

  #--
  # Alternate implementation, this yields each search entry to the caller as
  # it are received.
  #
  # TODO: certain search parameters are hardcoded.
  # TODO: if we mis-parse the server results or the results are wrong, we
  # can block forever. That's because we keep reading results until we get a
  # type-5 packet, which might never come. We need to support the time-limit
  # in the protocol.
  #++
  def search(args = nil)
    args ||= {}
    options = prepare_search_args(args)

    # filtering, scoping, search base
    # filter: https://tools.ietf.org/html/rfc4511#section-4.5.1.7
    # base:   https://tools.ietf.org/html/rfc4511#section-4.5.1.1
    # scope:  https://tools.ietf.org/html/rfc4511#section-4.5.1.2

    # attr handling
    # attrs:      https://tools.ietf.org/html/rfc4511#section-4.5.1.8
    # attrs_only: https://tools.ietf.org/html/rfc4511#section-4.5.1.6

    # references
    # refs:  https://tools.ietf.org/html/rfc4511#section-4.5.3
    # deref: https://tools.ietf.org/html/rfc4511#section-4.5.1.3

    # limiting, paging, sorting
    # size: https://tools.ietf.org/html/rfc4511#section-4.5.1.4
    # time: https://tools.ietf.org/html/rfc4511#section-4.5.1.5

    # An interesting value for the size limit would be close to A/D's
    # built-in page limit of 1000 records, but openLDAP newer than version
    # 2.2.0 chokes on anything bigger than 126. You get a silent error that
    # is easily visible by running slapd in debug mode. Go figure.
    #
    # Changed this around 06Sep06 to support a caller-specified search-size
    # limit. Because we ALWAYS do paged searches, we have to work around the
    # problem that it's not legal to specify a "normal" sizelimit (in the
    # body of the search request) that is larger than the page size we're
    # requesting. Unfortunately, I have the feeling that this will break
    # with LDAP servers that don't support paged searches!!!
    #
    # (Because we pass zero as the sizelimit on search rounds when the
    # remaining limit is larger than our max page size of 126. In these
    # cases, I think the caller's search limit will be ignored!)
    #
    # CONFIRMED: This code doesn't work on LDAPs that don't support paged
    # searches when the size limit is larger than 126. We're going to have
    # to do a root-DSE record search and not do a paged search if the LDAP
    # doesn't support it. Yuck.
    rfc2696_cookie = [126, ""]
    result_pdu = nil
    n_results = 0
    paged = options[:paged]

    message_id = next_msgid
    register_inbox(message_id)

    instrument "search.net_ldap_connection",
               message_id: message_id,
               filter:     options[:filter],
               base:       options[:base],
               scope:      options[:scope],
               size:       options[:size],
               time:       options[:time],
               sort:       options[:sort_controls],
               referrals:  options[:return_referrals],
               deref:      options[:deref],
               attributes: options[:attributes] do |payload|
      loop do
        # should collect this into a private helper to clarify the structure
        query_limit = 0
        if options[:size] > 0
          query_limit = if paged
                          (((options[:size] - n_results) < 126) ? (options[:size] - n_results) : 0)
                        else
                          options[:size]
                        end
        end

        request, controls = build_search_request(options, query_limit, rfc2696_cookie)

        write(request, controls, message_id)

        result_pdu = nil
        result_controls = []

        while pdu = queued_read(message_id)
          case pdu.app_tag
          when Net::LDAP::PDU::SearchReturnedData
            n_results += 1
            yield pdu.search_entry if block_given?
          when Net::LDAP::PDU::SearchResultReferral
            if options[:return_referrals]
              if block_given?
                se = Net::LDAP::Entry.new
                se[:search_referrals] = (pdu.search_referrals || [])
                yield se
              end
            end
          when Net::LDAP::PDU::SearchResult
            result_pdu = pdu
            result_controls = pdu.result_controls
            if options[:return_referrals] && pdu.result_code == Net::LDAP::ResultCodeReferral
              if block_given?
                se = Net::LDAP::Entry.new
                se[:search_referrals] = (pdu.search_referrals || [])
                yield se
              end
            end
            break
          else
            raise Net::LDAP::ResponseTypeInvalidError, "invalid response-type in search: #{pdu.app_tag}"
          end
        end

        if result_pdu.nil?
          raise Net::LDAP::ResponseMissingOrInvalidError, "response missing"
        end

        # count number of pages of results
        payload[:page_count] ||= 0
        payload[:page_count]  += 1

        # When we get here, we have seen a type-5 response. If there is no
        # error AND there is an RFC-2696 cookie, then query again for the next
        # page of results. If not, we're done. Don't screw this up or we'll
        # break every search we do.
        #
        # Noticed 02Sep06, look at the read_ber call in this loop, shouldn't
        # that have a parameter of AsnSyntax? Does this just accidentally
        # work? According to RFC-2696, the value expected in this position is
        # of type OCTET STRING, covered in the default syntax supported by
        # read_ber, so I guess we're ok.
        more_pages = false
        if result_pdu.result_code == Net::LDAP::ResultCodeSuccess and result_controls
          result_controls.each do |c|
            if c.oid == Net::LDAP::LDAPControls::PAGED_RESULTS
              # just in case some bogus server sends us more than 1 of these.
              more_pages = false
              if c.value and c.value.length > 0
                cookie = c.value.read_ber[1]
                more_pages = !!(cookie and cookie.length > 0)
                rfc2696_cookie[1] = cookie if more_pages
              end
            end
          end
        end

        break unless more_pages
      end # loop

      # track total result count
      payload[:result_count] = n_results

      result_pdu || OpenStruct.new(:status => :failure, :result_code => Net::LDAP::ResultCodeOperationsError, :message => "Invalid search")
    end # instrument
  ensure

    cleanup_inbox(message_id)
  end

  # Internal: Normalize and validate search arguments for both the blocking
  # #search and the concurrent #begin_search request paths.
  def prepare_search_args(args)
    # filtering, scoping, search base
    # filter: https://tools.ietf.org/html/rfc4511#section-4.5.1.7
    # base:   https://tools.ietf.org/html/rfc4511#section-4.5.1.1
    # scope:  https://tools.ietf.org/html/rfc4511#section-4.5.1.2
    filter = args[:filter] || Net::LDAP::Filter.eq("objectClass", "*")
    base   = args[:base]
    scope  = args[:scope] || Net::LDAP::SearchScope_WholeSubtree

    # attr handling
    # attrs:      https://tools.ietf.org/html/rfc4511#section-4.5.1.8
    # attrs_only: https://tools.ietf.org/html/rfc4511#section-4.5.1.6
    attrs  = Array(args[:attributes])
    attrs_only = args[:attributes_only] == true

    # references
    # refs:  https://tools.ietf.org/html/rfc4511#section-4.5.3
    # deref: https://tools.ietf.org/html/rfc4511#section-4.5.1.3
    refs   = args[:return_referrals] == true
    deref  = args[:deref] || Net::LDAP::DerefAliases_Never

    # limiting, paging, sorting
    # size: https://tools.ietf.org/html/rfc4511#section-4.5.1.4
    # time: https://tools.ietf.org/html/rfc4511#section-4.5.1.5
    size   = args[:size].to_i
    time   = args[:time].to_i
    paged  = args[:paged_searches_supported]
    sort   = args.fetch(:sort_controls, false)

    # arg validation
    raise ArgumentError, "search base is required" unless base
    raise ArgumentError, "invalid search-size" unless size >= 0
    raise ArgumentError, "invalid search scope" unless Net::LDAP::SearchScopes.include?(scope)
    raise ArgumentError, "invalid alias dereferencing value" unless Net::LDAP::DerefAliasesArray.include?(deref)

    # arg transforms
    filter = Net::LDAP::Filter.construct(filter) if filter.is_a?(String)
    ber_attrs = attrs.map { |attr| attr.to_s.to_ber }
    ber_sort  = encode_sort_controls(sort)

    {
      :args => args,
      :filter => filter,
      :base => base,
      :scope => scope,
      :attributes => attrs,
      :ber_attributes => ber_attrs,
      :attributes_only => attrs_only,
      :return_referrals => refs,
      :deref => deref,
      :size => size,
      :time => time,
      :paged => paged,
      :sort_controls => sort,
      :ber_sort => ber_sort,
    }
  end
  private :prepare_search_args

  # Internal: Build one page of a search request. Returns [request, controls].
  def build_search_request(options, query_limit, rfc2696_cookie)
    request = [
      options[:base].to_ber,
      options[:scope].to_ber_enumerated,
      options[:deref].to_ber_enumerated,
      query_limit.to_ber, # size limit
      options[:time].to_ber,
      options[:attributes_only].to_ber,
      options[:filter].to_ber,
      options[:ber_attributes].to_ber_sequence,
    ].to_ber_appsequence(Net::LDAP::PDU::SearchRequest)

    # rfc2696_cookie sometimes contains binary data from Microsoft Active
    # Directory; this breaks when calling to_ber. (Can't force binary data
    # to UTF-8.) We have to disable paging (even though the server supports
    # it) to get around this...
    paged = options[:paged]
    ber_sort = options[:ber_sort]
    user_controls = options[:args].fetch(:controls, [])
    controls = []
    controls <<
      [
        Net::LDAP::LDAPControls::PAGED_RESULTS.to_ber,
        # Criticality MUST be false to interoperate with normal LDAPs.
        false.to_ber,
        rfc2696_cookie.map(&:to_ber).to_ber_sequence.to_s.to_ber,
      ].to_ber_sequence if paged
    controls << ber_sort if ber_sort
    if controls.empty? && user_controls.empty?
      controls = nil
    else
      controls += user_controls
      controls = controls.to_ber_contextspecific(0)
    end

    [request, controls]
  end
  private :build_search_request

  # Internal: Remove a blocking inbox, instrumenting any unread leftovers.
  def cleanup_inbox(message_id)
    messages = @registry_mutex.synchronize { @inboxes.delete(message_id) }
    return if messages.nil?

    leftovers = []
    leftovers << messages.pop(true) until messages.empty?
    unless leftovers.empty?
      instrument "search_messages_unread.net_ldap_connection",
                 :message_id => message_id, :messages => leftovers
    end
  end
  private :cleanup_inbox

  ##
  # Begin a search without blocking for its result. The returned
  # Net::LDAP::Operation lets the caller stream entries with
  # Net::LDAP::Operation#each_entry, wait for the terminal result with
  # Net::LDAP::Operation#result, or abandon the search with
  # Net::LDAP::Operation#cancel (RFC 3909).
  #
  # The request uses the same arguments as #search. RFC 2696 paged searches
  # are followed transparently on the operation's message ID; entries from
  # every page arrive on the same Operation and only the final SearchResult
  # terminates it.
  def begin_search(args = nil)
    args ||= {}
    options = prepare_search_args(args)
    operation = register_operation(:search)
    message_id = operation.message_id
    rfc2696_cookie = [126, ""]

    initial_limit = options[:size] > 0 && !options[:paged] ? options[:size] : 0
    request, controls = build_search_request(options, initial_limit, rfc2696_cookie)

    page_count = 0
    operation.continuation = lambda do |result_pdu|
      next_cookie = next_search_page?(result_pdu)
      next false unless next_cookie

      rfc2696_cookie[1] = next_cookie
      query_limit = page_query_limit(options[:size], operation.entry_count)
      page_request, page_controls =
        build_search_request(options, query_limit, rfc2696_cookie)
      write(page_request, page_controls, message_id)
      page_count += 1
      true
    end

    instrument "search.net_ldap_connection",
               :message_id => message_id,
               :filter => options[:filter],
               :base => options[:base],
               :scope => options[:scope],
               :size => options[:size],
               :time => options[:time],
               :sort => options[:sort_controls],
               :referrals => options[:return_referrals],
               :deref => options[:deref],
               :attributes => options[:attributes] do
      write(request, controls, message_id)
    end

    operation
  end

  ##
  # Begin an LDAP Compare request (RFC 4511 section 4.10) without blocking
  # for the result. Returns a Net::LDAP::Operation whose #result yields the
  # CompareResponse PDU (result code CompareTrue / CompareFalse / error).
  #
  # - :dn:        the entry to compare (required)
  # - :attribute: the attribute description (required)
  # - :value:     the assertion value (required)
  def begin_compare(args)
    dn = args[:dn]
    attribute = args[:attribute]
    value = args[:value]
    raise ArgumentError, "compare dn is required" if dn.nil? || dn.to_s.empty?
    raise ArgumentError, "compare attribute is required" if attribute.nil? || attribute.to_s.empty?
    raise ArgumentError, "compare value is required" if value.nil?

    operation = register_operation(:compare)
    request = [
      dn.to_ber,
      [attribute.to_s.to_ber, value.to_ber].to_ber_sequence,
    ].to_ber_appsequence(Net::LDAP::PDU::CompareRequest)
    controls = controls_to_ber(args[:controls])

    instrument "compare.net_ldap_connection",
               :message_id => operation.message_id, :dn => dn,
               :attribute => attribute do
      write(request, controls, operation.message_id)
    end

    operation
  end

  # Internal: Blocking Compare used by Net::LDAP#compare.
  def compare(args)
    operation = begin_compare(args)
    result = operation.result
    unless result && result.app_tag == Net::LDAP::PDU::CompareResponse
      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
    end
    result
  end

  # Internal: Send an RFC 3909 Cancel extended request for +operation+ and
  # return the Operation tracking the cancel request itself. The target
  # operation is separately marked canceled when its own termination result
  # is routed (or synthesized on close).
  def cancel_operation(operation)
    cancel = register_operation(:cancel)
    request_value = operation.message_id.to_ber
    request = [
      Net::LDAP::CancelRequestOid.to_ber_contextspecific(0),
      request_value,
    ].to_ber_appsequence(Net::LDAP::PDU::ExtendedRequest)

    instrument "cancel.net_ldap_connection",
               :message_id => cancel.message_id,
               :cancel_message_id => operation.message_id do
      write(request, nil, cancel.message_id)
    end

    cancel
  end

  # Internal: Encode a controls argument, or nil when there are none.
  def controls_to_ber(controls)
    return nil if controls.nil? || (controls.respond_to?(:empty?) && controls.empty?)
    controls.to_ber_contextspecific(0)
  end
  private :controls_to_ber

  # Internal: Return the next RFC 2696 cookie from a successful page result,
  # or nil when there are no more pages.
  def next_search_page?(result_pdu)
    return nil unless result_pdu.result_code == Net::LDAP::ResultCodeSuccess
    controls = result_pdu.result_controls
    return nil unless controls

    cookie = nil
    controls.each do |control|
      next unless control.oid == Net::LDAP::LDAPControls::PAGED_RESULTS
      if control.value && control.value.length > 0
        value = control.value.read_ber
        possible = value && value[1]
        cookie = possible if possible && possible.length > 0
      end
    end
    cookie
  end
  private :next_search_page?

  # Internal: Per-query size limit for a page, mirroring #search.
  def page_query_limit(size, n_results)
    return 0 unless size > 0
    ((size - n_results) < 126) ? (size - n_results) : 0
  end
  private :page_query_limit

  MODIFY_OPERATIONS = { #:nodoc:
    :add => 0,
    :delete => 1,
    :replace => 2,
  }

  def self.modify_ops(operations)
    ops = []
    if operations
      operations.each do |op, attrib, values|
        # TODO, fix the following line, which gives a bogus error if the
        # opcode is invalid.
        op_ber = MODIFY_OPERATIONS[op.to_sym].to_ber_enumerated
        values = [values].flatten.map { |v| v.to_ber if v }.to_ber_set
        values = [attrib.to_s.to_ber, values].to_ber_sequence
        ops << [op_ber, values].to_ber
      end
    end
    ops
  end

  #--
  # TODO: need to support a time limit, in case the server fails to respond.
  # TODO: We're throwing an exception here on empty DN. Should return a
  # proper error instead, probaby from farther up the chain.
  # TODO: If the user specifies a bogus opcode, we'll throw a confusing
  # error here ("to_ber_enumerated is not defined on nil").
  #++
  def modify(args)
    modify_dn = args[:dn] or raise "Unable to modify empty DN"
    ops = self.class.modify_ops args[:operations]

    message_id = next_msgid
    request    = [
      modify_dn.to_ber,
      ops.to_ber_sequence,
    ].to_ber_appsequence(Net::LDAP::PDU::ModifyRequest)

    controls = args.fetch(:controls, nil)
    unless controls.nil?
      controls = controls.to_ber_contextspecific(0)
    end

    write(request, controls, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::ModifyResponse
      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
    end

    pdu
  end

  ##
  # Password Modify
  #
  # http://tools.ietf.org/html/rfc3062
  #
  # passwdModifyOID OBJECT IDENTIFIER ::= 1.3.6.1.4.1.4203.1.11.1
  #
  # PasswdModifyRequestValue ::= SEQUENCE {
  #   userIdentity    [0]  OCTET STRING OPTIONAL
  #   oldPasswd       [1]  OCTET STRING OPTIONAL
  #   newPasswd       [2]  OCTET STRING OPTIONAL }
  #
  # PasswdModifyResponseValue ::= SEQUENCE {
  #   genPasswd       [0]     OCTET STRING OPTIONAL }
  #
  # Encoded request:
  #
  #   00\x02\x01\x02w+\x80\x171.3.6.1.4.1.4203.1.11.1\x81\x100\x0E\x81\x05old\x82\x05new
  #
  def password_modify(args)
    dn = args[:dn]
    raise ArgumentError, 'DN is required' if !dn || dn.empty?

    ext_seq = [Net::LDAP::PasswdModifyOid.to_ber_contextspecific(0)]

    pwd_seq = []
    pwd_seq << dn.to_ber(0x80)
    pwd_seq << args[:old_password].to_ber(0x81) unless args[:old_password].nil?
    pwd_seq << args[:new_password].to_ber(0x82) unless args[:new_password].nil?
    ext_seq << pwd_seq.to_ber_sequence.to_ber(0x81)

    request = ext_seq.to_ber_appsequence(Net::LDAP::PDU::ExtendedRequest)

    message_id = next_msgid

    write(request, nil, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::ExtendedResponse
      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
    end

    pdu
  end

  #--
  # TODO: need to support a time limit, in case the server fails to respond.
  # Unlike other operation-methods in this class, we return a result hash
  # rather than a simple result number. This is experimental, and eventually
  # we'll want to do this with all the others. The point is to have access
  # to the error message and the matched-DN returned by the server.
  #++
  def add(args)
    add_dn = args[:dn] or raise Net::LDAP::EmptyDNError, "Unable to add empty DN"
    add_attrs = []
    a = args[:attributes] and a.each do |k, v|
      add_attrs << [k.to_s.to_ber, Array(v).map(&:to_ber).to_ber_set].to_ber_sequence
    end

    message_id = next_msgid
    request    = [add_dn.to_ber, add_attrs.to_ber_sequence].to_ber_appsequence(Net::LDAP::PDU::AddRequest)

    controls = args.fetch(:controls, nil)
    unless controls.nil?
      controls = controls.to_ber_contextspecific(0)
    end

    write(request, controls, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::AddResponse
      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
    end

    pdu
  end

  #--
  # TODO: need to support a time limit, in case the server fails to respond.
  #++
  def rename(args)
    old_dn = args[:olddn] or raise "Unable to rename empty DN"
    new_rdn = args[:newrdn] or raise "Unable to rename to empty RDN"
    delete_attrs = args[:delete_attributes] ? true : false
    new_superior = args[:new_superior]

    message_id = next_msgid
    request    = [old_dn.to_ber, new_rdn.to_ber, delete_attrs.to_ber]
    request   << new_superior.to_ber_contextspecific(0) unless new_superior == nil

    write(request.to_ber_appsequence(Net::LDAP::PDU::ModifyRDNRequest), nil, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::ModifyRDNResponse
      raise Net::LDAP::ResponseMissingOrInvalidError.new "response missing or invalid"
    end

    pdu
  end

  #--
  # TODO, need to support a time limit, in case the server fails to respond.
  #++
  def delete(args)
    dn = args[:dn] or raise "Unable to delete empty DN"
    controls   = args.include?(:control_codes) ? args[:control_codes].to_ber_control : nil #use nil so we can compact later
    message_id = next_msgid
    request    = dn.to_s.to_ber_application_string(Net::LDAP::PDU::DeleteRequest)

    write(request, controls, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::DeleteResponse
      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
    end

    pdu
  end

  def ldapwhoami
    ext_seq = [Net::LDAP::WhoamiOid.to_ber_contextspecific(0)]
    request = ext_seq.to_ber_appsequence(Net::LDAP::PDU::ExtendedRequest)

    message_id = next_msgid

    write(request, nil, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::ExtendedResponse
      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
    end

    pdu
  end

  # Internal: Returns a Socket like object used internally to communicate with
  # LDAP server.
  #
  # Typically a TCPSocket, but can be a OpenSSL::SSL::SSLSocket
  def socket
    return @conn if defined?(@conn) && !@conn.nil?

    # First refactoring uses the existing methods open_connection and
    # prepare_socket to set @conn. Next cleanup would centralize connection
    # handling here.
    if @server[:socket]
      prepare_socket(@server)
    else
      @server[:hosts] = [[@server[:host], @server[:port]]] if @server[:hosts].nil?
      open_connection(@server)
    end

    @conn
  end

  private

  # Wrap around Socket.tcp to normalize with other Socket initializers
  class DefaultSocket
    def self.new(host, port, socket_opts = {})
      Socket.tcp(host, port, **socket_opts)
    end
  end
end # class Connection
