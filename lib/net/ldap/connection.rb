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

    # Only one thread may read BER PDUs off the socket at a time. Every
    # read goes through #pump/#read, which hold this lock.
    @read_mutex = Mutex.new

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
    finalize_pending_operations
    if defined?(@conn) && @conn
      @conn.close
      @conn = nil
    end
  end

  # Public: All outstanding operations keyed by message ID. Unsolicited
  # notifications (message ID 0) are never placed here.
  #
  # Returns the operations Hash.
  def operations
    @operations ||= {}
  end

  # Public: Unsolicited notifications received with message ID 0. Such
  # PDUs are never attributed to a request.
  #
  # http://tools.ietf.org/html/rfc4511#section-4.4
  #
  # Returns an Array of Net::LDAP::PDU objects.
  def unsolicited_notifications
    @unsolicited_notifications ||= []
  end

  # Public: Read exactly one PDU from the socket (the single BER read
  # entry point) and route it to the operation it belongs to.
  #
  # PDUs are attributed by message ID: responses to one outstanding
  # operation never get delivered to another. Unsolicited notifications
  # (message ID 0) are collected via #unsolicited_notifications. PDUs that
  # arrive after their operation has finished, or whose ID is not known,
  # are dropped and instrumented so a late entry can never be handed to a
  # different (or future) operation.
  #
  # Returns the routed Net::LDAP::PDU, or nil at end-of-stream (in which
  # case all outstanding operations are finalized with a closed result).
  def pump
    @read_mutex.synchronize do
      pdu = read
      if pdu.nil?
        finalize_pending_operations
        return nil
      end
      route_pdu(pdu)
      pdu
    end
  end

  # Public: Pump PDUs off the socket until every outstanding operation
  # listed in +operation_ids+ has finished, or the socket reaches EOF.
  #
  # This is cooperative: it runs on the caller's thread. Other operations
  # remain serviceable while waiting because every PDU (whatever its
  # message ID) is read and routed here.
  def process_messages(operation_ids)
    ids = Array(operation_ids)
    until ids.all? { |id| operations[id].nil? || operations[id].finished? }
      break if pump.nil?
    end
  end

  # Public: start a background thread that is the single reader of the
  # socket. Every PDU is routed through #pump, so the issuing threads only
  # block on Operation#wait / Operation#entries without doing their own
  # socket reads. The thread exits when #pump returns nil (end of stream)
  # or when #close finalizes the outstanding operations.
  #
  # Returns the Thread.
  def start_message_loop
    raise Net::LDAP::Error, "message loop already running" if @message_loop&.alive?
    @message_loop = Thread.new do
      begin
        while true
          break if pump.nil?
        end
      rescue IOError, SystemCallError, OpenSSL::SSL::SSLError, Net::LDAP::Error
        finalize_pending_operations
      end
    end
    @message_loop
  end

  # Public: stop the background message loop started with
  # #start_message_loop, if any. Pending operations are left as-is unless
  # the connection itself is closed.
  def stop_message_loop
    thread = @message_loop
    @message_loop = nil
    thread&.join
  end

  # Public: register an Operation that has been sent on this connection.
  #
  # Raises Net::LDAP::Error if the message ID is already in use, which
  # guarantees that a late response can never be delivered to a new
  # operation that reused a number.
  def register_operation(operation)
    if operations.key?(operation.message_id)
      raise Net::LDAP::Error,
            "message ID #{operation.message_id} is already in use"
    end
    operations[operation.message_id] = operation
  end

  # Public: Send an RFC 3909 Cancel extended request for +operation+ and
  # return the Operation tracking the cancel request's *own* result,
  # separately from the termination result of the target operation.
  #
  # http://tools.ietf.org/html/rfc3909
  def cancel_operation(operation)
    request = [
      Net::LDAP::CancelOid.to_ber_contextspecific(0),
      cancel_request_value(operation.message_id),
    ].to_ber_appsequence(Net::LDAP::PDU::ExtendedRequest)

    message_id = next_msgid
    cancel_op = Net::LDAP::Operation.new(self, message_id, :cancel)
    register_operation(cancel_op)
    begin
      write(request, nil, message_id)
    rescue StandardError
      operations.delete(message_id)
      raise
    end
    cancel_op
  end

  # RFC 3909 cancelRequestValue is an OCTET STRING whose value is the
  # BER-encoded message ID of the operation to cancel, wrapped in the
  # context-specific [1] tag of the ExtendedRequest.
  def cancel_request_value(message_id)
    message_id.to_ber.to_ber_contextspecific(1)
  end
  private :cancel_request_value

  # Public: Route a parsed PDU to its owner. Kept distinct from #pump so
  # tests (and a future reader thread) can feed already-parsed PDUs
  # through the same attribution logic.
  def route_pdu(pdu)
    if pdu.message_id.zero?
      unsolicited_notifications << pdu
      instrument "unsolicited_notification.net_ldap_connection",
                 message_id: 0, app_tag: pdu.app_tag, pdu: pdu
      return
    end

    operation = operations[pdu.message_id]
    if operation.nil? || operation.finished?
      instrument "unmatched_message.net_ldap_connection",
                 message_id: pdu.message_id,
                 app_tag: pdu.app_tag,
                 pdu: pdu
      return
    end

    status = operation.deliver(pdu)
    operations.delete(pdu.message_id) if status == :finished
  end

  # Public: finalize every outstanding operation with its own terminal
  # "connection closed" result. Each operation gets a distinct PDU that
  # carries its own message ID and the application tag appropriate to the
  # operation.
  def finalize_pending_operations
    pending = operations.values
    operations.clear
    pending.each do |operation|
      operation.close_with(closed_result_pdu(operation))
    end
  end

  # Public: start a search without blocking on its result. Returns an
  # Net::LDAP::Operation. The search request is written immediately; the
  # caller is free to start other operations, then consume entries with
  # Operation#entries/#drain_entries and the terminal result with
  # Operation#wait.
  def start_search(args = nil, &on_entry)
    prepared = prepare_search_args(args)
    message_id = next_msgid
    operation = Net::LDAP::Operation.new(self, message_id, :search,
                                         return_referrals: prepared[:refs],
                                         &on_entry)
    operation.continue = proc { |op, result_pdu| continue_paged_search(prepared, op, result_pdu) }
    register_operation(operation)
    begin
      request, controls = build_search_request(prepared, message_id, 0)
      write(request, controls, message_id)
    rescue StandardError
      operations.delete(message_id)
      raise
    end
    operation
  end

  # Public: start a compare without blocking on its result. Returns an
  # Net::LDAP::Operation. Result code Net::LDAP::ResultCodeCompareTrue (6)
  # means the assertion held; ResultCodeCompareFalse (5) means it did
  # not (both are "successful" protocol results).
  #
  # http://tools.ietf.org/html/rfc4511#section-4.10
  def start_compare(args)
    request = [
      args[:dn].to_s.to_ber,
      [
        args[:attribute].to_s.to_ber,
        Array(args[:value]).first.to_s.to_ber,
      ].to_ber_sequence,
    ].to_ber_appsequence(Net::LDAP::PDU::CompareRequest)

    message_id = next_msgid
    operation = Net::LDAP::Operation.new(self, message_id, :compare)
    register_operation(operation)
    begin
      write(request, nil, message_id)
    rescue StandardError
      operations.delete(message_id)
      raise
    end
    operation
  end

  # Internal: Reads messages by ID from a queue, falling back to reading from
  # the connected socket until a message matching the ID is read. Any messages
  # with mismatched IDs gets queued for subsequent reads by the origin of that
  # message ID.
  #
  # Returns a Net::LDAP::PDU object or nil.
  def queued_read(message_id)
    if pdu = message_queue[message_id].shift
      return pdu
    end

    # read messages until we have a match for the given message_id
    while pdu = read
      return pdu if pdu.message_id == message_id

      message_queue[pdu.message_id].push pdu
      next
    end

    pdu
  end

  # Internal: The internal queue of messages, read from the socket, grouped by
  # message ID.
  #
  # Used by `queued_read` to return messages sent by the server with the given
  # ID. If no messages are queued for that ID, `queued_read` will `read` from
  # the socket and queue messages that don't match the given ID for other
  # readers.
  #
  # Returns the message queue Hash.
  def message_queue
    @message_queue ||= Hash.new do |hash, key|
      hash[key] = []
    end
  end

  # Internal: Reads and parses data from the configured connection.
  #
  # - syntax: the BER syntax to use to parse the read data with
  #
  # Returns parsed Net::LDAP::PDU object.
  def read(syntax = Net::LDAP::AsnSyntax)
    ber_object =
      instrument "read.net_ldap_connection", :syntax => syntax do |payload|
        socket.read_ber(syntax) do |id, content_length|
          payload[:object_type_id] = id
          payload[:content_length] = content_length
        end
      end

    return unless ber_object

    instrument "parse_pdu.net_ldap_connection" do |payload|
      pdu = payload[:pdu]  = Net::LDAP::PDU.new(ber_object)

      payload[:message_id] = pdu.message_id
      payload[:app_tag]    = pdu.app_tag

      pdu
    end
  end
  private :read

  # Internal: Write a BER formatted packet with the next message id to the
  # configured connection.
  #
  # - request: required BER formatted request
  # - controls: optional BER formatted controls
  #
  # Returns the return value from writing to the connection, which in some
  # cases is the Integer number of bytes written to the socket.
  def write(request, controls = nil, message_id = next_msgid)
    instrument "write.net_ldap_connection" do |payload|
      packet = [message_id.to_ber, request, controls].compact.to_ber_sequence
      payload[:content_length] = socket.write(packet)
    end
  end
  private :write

  def next_msgid
    @msgid ||= 0
    @msgid += 1
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

  # Validate and normalize the arguments shared by the blocking #search
  # path and the concurrent #start_search path.
  def prepare_search_args(args)
    args ||= {}

    base   = args[:base]
    scope  = args[:scope] || Net::LDAP::SearchScope_WholeSubtree
    deref  = args[:deref] || Net::LDAP::DerefAliases_Never
    size   = args[:size].to_i
    time   = args[:time].to_i

    raise ArgumentError, "search base is required" unless base
    raise ArgumentError, "invalid search-size" unless size >= 0
    raise ArgumentError, "invalid search scope" unless Net::LDAP::SearchScopes.include?(scope)
    raise ArgumentError, "invalid alias dereferencing value" unless Net::LDAP::DerefAliasesArray.include?(deref)

    filter = args[:filter] || Net::LDAP::Filter.eq("objectClass", "*")
    filter = Net::LDAP::Filter.construct(filter) if filter.is_a?(String)

    {
      base: base,
      scope: scope,
      deref: deref,
      size: size,
      time: time,
      attrs_only: args[:attributes_only] == true,
      filter: filter,
      attrs: Array(args[:attributes]),
      refs: args[:return_referrals] == true,
      paged: args[:paged_searches_supported],
      sort: args.fetch(:sort_controls, false),
      user_controls: args.fetch(:controls, []),
      rfc2696_cookie: [126, ""],
    }
  end
  private :prepare_search_args

  # Build one SearchRequest BER packet (and its controls) for the given
  # page. +n_results+ is the number of entries already returned across
  # previous pages.
  def build_search_request(prepared, _message_id, n_results)
    size  = prepared[:size]
    paged = prepared[:paged]

    query_limit = 0
    if size > 0
      query_limit = if paged
                      ((size - n_results) < 126 ? (size - n_results) : 0)
                    else
                      size
                    end
    end

    ber_attrs = prepared[:attrs].map { |attr| attr.to_s.to_ber }
    request = [
      prepared[:base].to_ber,
      prepared[:scope].to_ber_enumerated,
      prepared[:deref].to_ber_enumerated,
      query_limit.to_ber,
      prepared[:time].to_ber,
      prepared[:attrs_only].to_ber,
      prepared[:filter].to_ber,
      ber_attrs.to_ber_sequence,
    ].to_ber_appsequence(Net::LDAP::PDU::SearchRequest)

    ber_sort = encode_sort_controls(prepared[:sort])
    controls = []
    # rfc2696_cookie sometimes contains binary data from Microsoft Active Directory
    # this breaks when calling to_ber. (Can't force binary data to UTF-8)
    # we have to disable paging (even though server supports it) to get around this...
    controls <<
      [
        Net::LDAP::LDAPControls::PAGED_RESULTS.to_ber,
        # Criticality MUST be false to interoperate with normal LDAPs.
        false.to_ber,
        prepared[:rfc2696_cookie].map(&:to_ber).to_ber_sequence.to_s.to_ber,
      ].to_ber_sequence if paged
    controls << ber_sort if ber_sort
    if controls.empty? && prepared[:user_controls].empty?
      controls = nil
    else
      controls += prepared[:user_controls]
      controls = controls.to_ber_contextspecific(0)
    end

    [request, controls]
  end
  private :build_search_request

  # Send the next page request for a paged search driven through the
  # concurrent operation interface.
  def continue_paged_search(prepared, operation, result_pdu)
    result_pdu.result_controls.each do |control|
      next unless control.oid == Net::LDAP::LDAPControls::PAGED_RESULTS
      next if control.value.nil? || control.value.empty?
      cookie = control.value.read_ber[1]
      next if cookie.nil? || cookie.empty?
      prepared[:rfc2696_cookie][1] = cookie
    end
    request, controls = build_search_request(prepared, operation.message_id,
                                             operation.entry_count)
    write(request, controls, operation.message_id)
  end
  private :continue_paged_search

  # Blocking compare: sends the assertion and waits for its own result,
  # regardless of any other outstanding operations on the connection.
  #
  # http://tools.ietf.org/html/rfc4511#section-4.10
  def compare(args)
    operation = start_compare(args)
    pdu = operation.wait
    unless pdu.app_tag == Net::LDAP::PDU::CompareResponse
      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
    end
    pdu
  end

  # Build the terminal PDU an operation receives when the connection is
  # closed before the server returned a result. Each operation gets its
  # own PDU carrying its own message ID and the response tag matching its
  # request type.
  def closed_result_pdu(operation)
    response_tag =
      case operation.kind
      when :search then Net::LDAP::PDU::SearchResult
      when :compare then Net::LDAP::PDU::CompareResponse
      else Net::LDAP::PDU::ExtendedResponse
      end
    result = Net::BER::BerIdentifiedArray.new([
      Net::LDAP::ResultCodeConnectionClosed,
      "",
      "connection closed",
    ])
    result.ber_identifier = response_tag
    Net::LDAP::PDU.new([operation.message_id, result])
  end
  private :closed_result_pdu

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
    prepared = prepare_search_args(args)

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
    result_pdu = nil
    n_results = 0

    message_id = next_msgid

    instrument "search.net_ldap_connection",
               message_id: message_id,
               filter:     prepared[:filter],
               base:       prepared[:base],
               scope:      prepared[:scope],
               size:       prepared[:size],
               time:       prepared[:time],
               sort:       prepared[:sort],
               referrals:  prepared[:refs],
               deref:      prepared[:deref],
               attributes: prepared[:attrs] do |payload|
      loop do
        request, controls = build_search_request(prepared, message_id, n_results)
        write(request, controls, message_id)

        result_pdu = nil
        result_controls = nil

        while pdu = queued_read(message_id)
          case pdu.app_tag
          when Net::LDAP::PDU::SearchReturnedData
            n_results += 1
            yield pdu.search_entry if block_given?
          when Net::LDAP::PDU::SearchResultReferral
            if prepared[:refs]
              if block_given?
                se = Net::LDAP::Entry.new
                se[:search_referrals] = (pdu.search_referrals || [])
                yield se
              end
            end
          when Net::LDAP::PDU::SearchResult
            result_pdu = pdu
            result_controls = pdu.result_controls
            if prepared[:refs] && pdu.result_code == Net::LDAP::ResultCodeReferral
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
                if cookie and cookie.length > 0
                  prepared[:rfc2696_cookie][1] = cookie
                  more_pages = true
                end
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

    # clean up message queue for this search
    messages = message_queue.delete(message_id)

    # in the exceptional case some messages were *not* consumed from the queue,
    # instrument the event but do not fail.
    if !messages.nil? && !messages.empty?
      instrument "search_messages_unread.net_ldap_connection",
                 message_id: message_id, messages: messages
    end
  end

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
