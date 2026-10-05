# -*- ruby encoding: utf-8 -*-
require 'uri'
require 'uri/ldap'
require 'uri/ldaps'

class Net::LDAP::Referral
  Target = Struct.new(:uri, :host, :port, :encryption, :base, :scope, :filter,
                      :attributes, :attributes_given, :hop, :source_url,
                      :raw_uri, keyword_init: true)
  Source = Struct.new(:url, :host, :port, :hop, :parent_url, :chain,
                      keyword_init: true)
  Event = Struct.new(:type, :url, :reason, :source_url, :hop, :result_code,
                     :error_message, :target, :raw_uri, keyword_init: true) do
    def to_h
      members.each_with_object({}) { |member, hash| hash[member] = self[member] }
    end
  end

  class URL
    SCOPES = {
      'base' => Net::LDAP::SearchScope_BaseObject,
      'one' => Net::LDAP::SearchScope_SingleLevel,
      'sub' => Net::LDAP::SearchScope_WholeSubtree,
    }.freeze

    attr_reader :uri, :base, :scope, :filter, :attributes, :attributes_given

    def self.parse(value, inherited)
      new(value, inherited).target
    end

    def initialize(value, inherited)
      @raw_value = value.to_s
      @inherited = inherited
      @uri = URI(@raw_value)
      raise ArgumentError, "unsupported LDAP referral scheme: #{@uri.scheme}" unless %w[ldap ldaps].include?(@uri.scheme)
      raise ArgumentError, 'LDAP referral must identify a host' if @uri.host.nil? || @uri.host.empty?

      parse_components
    end

    def target
      Target.new(
        uri: canonical_uri,
        raw_uri: @raw_value,
        host: @uri.host,
        port: @uri.port || (@uri.scheme == 'ldaps' ? 636 : 389),
        encryption: @uri.scheme == 'ldaps' ? { method: :simple_tls, tls_options: {} } : nil,
        base: @base,
        scope: @scope,
        filter: @filter,
        attributes: @attributes,
        attributes_given: @attributes_given,
        hop: @inherited[:hop].to_i + 1,
        source_url: @inherited[:source_url],
      )
    end

    private

    def parse_components
      attrlist, scopename, filtertext = (@uri.query || '').split('?', 4)

      @base = explicit_path? ? URI::DEFAULT_PARSER.unescape(@uri.path.sub(%r{\A/}, '')) : @inherited[:base]
      @scope = if scopename.nil?
                 @inherited[:scope]
               elsif scopename.empty?
                 Net::LDAP::SearchScope_BaseObject
               else
                 SCOPES.fetch(URI::DEFAULT_PARSER.unescape(scopename))
               end
      @filter = if filtertext.nil?
                  @inherited[:filter]
                elsif filtertext.empty?
                  Net::LDAP::Filter.eq('objectClass', '*')
               else
                  Net::LDAP::Filter.construct(URI::DEFAULT_PARSER.unescape(filtertext))
                end

      if attrlist.nil?
        @attributes = @inherited[:attributes]
        @attributes_given = @inherited[:attributes_given]
      else
        @attributes_given = true
        @attributes = URI::DEFAULT_PARSER.unescape(attrlist).split(',').reject(&:empty?)
      end
    end

    def canonical_uri
      attrs = @attributes_given ? @attributes.map { |a| URI::DEFAULT_PARSER.escape(a) }.join(',') : nil
      query = [attrs, SCOPES.key(@scope), @filter.to_s].compact.join('?')
      path = @base.empty? ? '/' : "/#{URI::DEFAULT_PARSER.escape(@base)}"
      URI::Generic.build(
        scheme: @uri.scheme,
        host: @uri.host,
        port: @uri.port,
        path: path,
        query: query.empty? ? nil : query,
      ).to_s
    end

    def explicit_path?
      authority_end = @raw_value.index('?') || @raw_value.length
      authority_start = @raw_value.index('://').to_i + 3
      slash = @raw_value.index('/', authority_start)
      slash && slash < authority_end
    end
  end

  class Result
    attr_accessor :result_code, :error_message, :matched_dn, :ldap_controls
    attr_reader :entries, :sources, :failures, :skipped, :referrals

    def initialize
      @entries = []
      @sources = []
      @failures = []
      @skipped = []
      @referrals = []
      @result_code = Net::LDAP::ResultCodeSuccess
      @error_message = ''
      @matched_dn = ''
      @ldap_controls = []
    end

    def success?
      @result_code == Net::LDAP::ResultCodeSuccess
    end

    def failure?
      !success?
    end

    def result
      {
        resultCode: @result_code,
        errorMessage: @error_message,
        matchedDN: @matched_dn,
      }
    end

    def result_controls
      @ldap_controls
    end

    def status
      success? ? :success : :failure
    end

    def referral_trace
      {
        sources: @sources.map(&:to_h),
        failures: @failures.map(&:to_h),
        skipped: @skipped.map(&:to_h),
        referrals: @referrals.map(&:to_h),
      }
    end
  end

  def initialize(connection, args, root_server, block)
    @connection = connection
    @args = args
    @root_server = root_server
    @block = block
    @result = Result.new
    @pending = []
    @entry_budget = args[:size].to_i
    @max_hops = args.fetch(:max_referral_hops, 10).to_i
  end

  def run
    args = normalize_search_args(@args)
    root_url = root_url(@root_server, args)
    root_source = make_source(root_url, @root_server[:host],
                              @root_server[:port], 0, nil, [root_url])
    @result.sources << root_source
    run_server(@connection, root_search_args(args), root_source)
    process_pending
    finalize_result
    @result
  end

  private

  def root_search_args(args)
    referral_search_args(args).merge(
      _referral_source: @result.sources.first,
      auth: @args[:_root_auth],
    )
  end

  def referral_search_args(args)
    args.merge(return_referrals: false, _referral_handler: method(:queue_referral))
  end

  def target_search_args(target)
    referral_search_args(normalize_search_args(@args)).merge(
      base: target.base,
      scope: target.scope,
      filter: target.filter,
      attributes: target.attributes,
      _attributes_given: target.attributes_given,
      size: remaining_budget,
      _referral_source: nil,
    )
  end

  def root_url(server, args)
    encryption = server[:encryption]
    scheme = encryption && encryption[:method] == :simple_tls ? 'ldaps' : 'ldap'
    port = server[:port] || (scheme == 'ldaps' ? 636 : 389)
    attrs = @args.key?(:attributes) ? Array(args[:attributes]).map { |a| URI::DEFAULT_PARSER.escape(a.to_s) }.join(',') : nil
    query = [attrs, URL::SCOPES.key(args[:scope]), args[:filter].to_s].compact.join('?')
    path = args[:base].empty? ? '/' : "/#{URI::DEFAULT_PARSER.escape(args[:base])}"
    URI::Generic.build(scheme: scheme, host: server[:host], port: port,
                       path: path, query: query.empty? ? nil : query).to_s
  end

  def process_pending
    until @pending.empty?
      item = @pending.shift
      @result.referrals << item[:event]
      if budget_exhausted?
        skip(item[:uri], item[:source], :result_budget_exceeded,
             'logical search result budget exceeded')
        next
      end
      follow(item[:uri], item[:source])
    end
  end

  def follow(uri, source)
    args = normalize_search_args(@args)
    inherited = {
      base: args[:base],
      scope: args[:scope],
      filter: args[:filter],
      attributes: args[:attributes],
      attributes_given: @args.key?(:attributes),
      hop: source.hop,
      source_url: source.url,
    }

    target = begin
      URL.parse(uri, inherited)
    rescue => error
      skip(uri, source, :invalid_url, error.message)
      return nil
    end

    if target.hop > @max_hops
      skip(uri, source, :hop_limit_exceeded, 'referral hop limit exceeded', target)
      return nil
    end
    if source.chain.include?(target.uri)
      skip(uri, source, :referral_cycle, 'referral cycle detected', target)
      return nil
    end

    decision = decide(uri, target)
    open_target(uri, target, decision, source) if decision
  end

  def decide(uri, target)
    policy = @args[:referral_policy]
    if policy.nil?
      skip(uri, nil, :no_policy, 'no referral policy allowed this target', target)
      return nil
    end

    decision = begin
      policy.call(target.to_h)
    rescue => error
      skip(uri, nil, :policy_error, error.message, target)
      return nil
    end

    normalize_decision(decision, uri, target)
  end

  def normalize_decision(decision, uri, target)
    decision = { allow: decision } if [true, false].include?(decision)
    decision ||= {}

    unless decision[:allow] == true
      skip(uri, nil, decision[:reason] || :not_allowed,
           decision[:reason] || 'referral target was not allowed by policy', target)
      return nil
    end

    auth = decision[:auth] || { method: :anonymous }
    valid_auth = auth.is_a?(Hash) && auth[:method] &&
                 (auth[:method] == :anonymous || !auth[:password].nil?)
    unless valid_auth
      skip(uri, nil, :invalid_auth, 'referral policy returned invalid authentication', target)
      return nil
    end

    decision.merge(auth: auth)
  end

  def open_target(uri, target, decision, source)
    return if budget_exhausted?

    target_source = make_source(target.uri, target.host, target.port, target.hop,
                                source.url, source.chain + [target.uri])
    @result.sources << target_source
    connection = nil

    server = {
      host: target.host,
      port: target.port,
      hosts: [[target.host, target.port]],
      encryption: decision.fetch(:encryption, nil) || target.encryption,
      connect_timeout: @root_server[:connect_timeout],
      socket_class: @root_server[:socket_class],
      instrumentation_service: @root_server[:instrumentation_service],
    }

    connection = Net::LDAP::Connection.new(server)
    bind_result = connection.bind(decision[:auth])
    unless bind_result.result_code == Net::LDAP::ResultCodeSuccess
      record_failure(target_source, uri, bind_result)
      return
    end

    run_server(connection, target_search_args(target).merge(_referral_source: target_source), target_source, uri)
  rescue Net::LDAP::Error, SocketError, SystemCallError => error
    record_failure(target_source || source, uri, error)
  ensure
    connection.close if connection
  end

  def run_server(connection, args, source, referral_uri = nil)
    pdu = connection.search_server(args) do |entry|
      next if budget_exhausted?
      entry.ldap_source = source.to_h
      @result.entries << entry
      @block.call(entry) if @block
    end
    unless pdu.result_code == Net::LDAP::ResultCodeSuccess
      record_failure(source, referral_uri, pdu)
    end
    pdu
  rescue Net::LDAP::Error, SocketError, SystemCallError => error
    record_failure(source, referral_uri, error)
  end

  def queue_referral(pdu, source)
    (pdu.search_referrals || []).each do |uri|
      event = Event.new(type: :referral, url: uri, source_url: source.url,
                        hop: source.hop, result_code: pdu.result_code,
                        raw_uri: uri)
      @pending << { uri: uri, source: source, event: event }
    end
  end

  def remaining_budget
    return 0 if @entry_budget <= 0
    [@entry_budget - @result.entries.length, 0].max
  end

  def budget_exhausted?
    @entry_budget > 0 && @result.entries.length >= @entry_budget
  end

  def make_source(url, host, port, hop, parent_url, chain)
    Source.new(url: url, host: host, port: port, hop: hop,
               parent_url: parent_url, chain: chain)
  end

  def normalize_search_args(args)
    filter = args[:filter] || Net::LDAP::Filter.eq('objectClass', '*')
    filter = Net::LDAP::Filter.construct(filter) if filter.is_a?(String)
    normalized = args.merge(
      scope: args[:scope] || Net::LDAP::SearchScope_WholeSubtree,
      filter: filter,
    )
    normalized[:attributes] = Array(args[:attributes]) if args.key?(:attributes)
    normalized
  end

  def skip(uri, source, reason, message, target = nil)
    event = Event.new(type: :skipped, url: target&.uri || uri,
                      raw_uri: uri, reason: reason, error_message: message,
                      source_url: source&.url, hop: target&.hop,
                      target: target&.to_h)
    @result.skipped << event
    notify(event)
  end

  def record_failure(source, uri, error)
    event = Event.new(
      type: :failure,
      url: source&.url,
      raw_uri: uri,
      source_url: source&.parent_url,
      hop: source&.hop,
      result_code: error.respond_to?(:result_code) ? error.result_code : Net::LDAP::ResultCodeOperationsError,
      error_message: error.respond_to?(:error_message) ? error.error_message : error.message,
    )
    @result.failures << event
    notify(event)
  end

  def notify(event)
    @args[:on_referral_event]&.call(event.to_h)
  end

  def finalize_result
    failure = @result.failures.last
    if failure
      @result.result_code = @result.entries.empty? ? failure.result_code : Net::LDAP::ResultCodeSuccess
      @result.error_message = failure.error_message if @result.entries.empty?
    end
    @result
  end
end
