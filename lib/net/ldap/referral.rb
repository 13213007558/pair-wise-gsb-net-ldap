# -*- ruby encoding: utf-8 -*-
require 'uri'

class Net::LDAP
  class InvalidLDAPURLError < Error; end

  class FailedReferralConnection
    attr_reader :result

    def initialize(result)
      @result = result
    end

    def search_with_events(_args)
      block_given? ? yield(:result, result) : result
    end

    def close; end
  end

  class ReferralEvent < Struct.new(:type, :url, :source, :target, :reason,
                                  :result, :hop, keyword_init: true)
    def skipped?
      type == :skipped
    end
  end

  class SearchReport
    attr_reader :entries, :referrals, :failures, :skipped, :hops,
                :result_count

    def initialize
      @entries = []
      @referrals = []
      @failures = []
      @skipped = []
      @hops = 0
      @result_count = 0
    end

    def entry(entry, source)
      @entries << [entry, source]
      @result_count += 1
    end

    def referral(url, source, target, hop)
      event = ReferralEvent.new(:type => :referral, :url => url,
                                :source => source, :target => target,
                                :hop => hop)
      @referrals << event
      event
    end

    def failure(source, result)
      event = ReferralEvent.new(:type => :failure, :source => source,
                                :result => result)
      @failures << event
      event
    end

    def skip(url, source, target, reason, hop)
      event = ReferralEvent.new(:type => :skipped, :url => url,
                                :source => source, :target => target,
                                :reason => reason, :hop => hop)
      @skipped << event
      event
    end

    def hop!
      @hops += 1
    end

    def success?
      failures.empty?
    end
  end

  class SearchAggregateResult
    attr_reader :report

    def initialize(report)
      @report = report
    end

    def result_code
      failure_result ? failure_result.result_code : ResultCodeSuccess
    end

    def success?
      report.failures.empty?
    end

    def status
      success? ? :success : :failure
    end

    def error_message
      return unless failure_result

      if failure_result.respond_to?(:error_message)
        failure_result.error_message
      elsif failure_result.respond_to?(:result)
        failure_result.result[:errorMessage]
      end
    end

    def matched_dn
      return unless failure_result.respond_to?(:result)

      failure_result.result[:matchedDN]
    end

    def search_referrals
      report.referrals.map(&:url)
    end

    def to_operation_result
      {
        :resultCode => result_code,
        :errorMessage => error_message,
        :matchedDN => matched_dn,
        :search_report => report,
        :referrals => report.referrals,
        :skipped_referrals => report.skipped,
        :failures => report.failures,
      }
    end

    private

    def failure_result
      report.failures.first&.result
    end
  end

  class ReferralURL
    SCOPES = {
      'base' => SearchScope_BaseObject,
      'one' => SearchScope_SingleLevel,
      'sub' => SearchScope_WholeSubtree,
    }.freeze

    attr_reader :url, :scheme, :host, :port, :dn, :scope, :filter,
                :attributes, :encryption

    def initialize(url, search_args = {})
      @url = url
      @search_args = search_args
      parse
    end

    def target_args
      args = @search_args.dup
      args[:host] = host
      args[:port] = port
      args[:base] = dn
      args[:scope] = scope
      args[:filter] = filter
      args[:attributes] = attributes
      args[:encryption] = encryption if encryption
      args.delete(:auth)
      args.delete(:follow_referrals)
      args.delete(:paged_searches_supported)
      args
    end

    def identity
      [scheme, host, port, dn, scope, filter, attributes].inspect
    end

    private

    def parse
      uri = URI.parse(url)
      unless uri.scheme && %w[ldap ldaps].include?(uri.scheme.downcase)
        raise InvalidLDAPURLError, "unsupported referral URL scheme: #{url}"
      end

      @scheme = uri.scheme.downcase
      inherit_host_and_port(uri)
      @encryption = { :method => :simple_tls, :tls_options => {} } if
        @scheme == 'ldaps'

      dn_value, attrs_value, scope_value, filter_value = components
      apply_dn(dn_value)
      apply_attributes(attrs_value)
      apply_scope(scope_value)
      apply_filter(filter_value)
    rescue URI::InvalidURIError, ArgumentError => e
      raise InvalidLDAPURLError, e.message
    end

    def inherit_host_and_port(uri)
      authority = url[%r{ldaps?://([^/?#]*)}im, 1]
      host_part, port_part = authority.to_s.split(':', 2)

      @host = if host_part.nil? || host_part.empty?
                @search_args[:host]
              else
                URI.decode_www_form_component(host_part)
              end
      default_port = @scheme == 'ldaps' ? 636 : URI::LDAP::DEFAULT_PORT
      @port = port_part ? Integer(port_part) : (@search_args[:port] || default_port)
    end

    def components
      remainder = url.sub(%r{ldaps?://[^/?#]*}im, '')
      path_part, = remainder.split('?', 2)
      dn_value = path_part.start_with?('/') ? path_part.sub(%r{^/}, '') : nil
      return [dn_value, nil, nil, nil] unless raw_query?

      query = remainder.split('?', 2).last
      values = query.split('?', 4)
      values.fill(nil, values.length...4)
      [dn_value, *values[0, 3]]
    end

    def raw_query?
      url.include?('?')
    end

    def apply_dn(value)
      @dn = value.nil? ? @search_args[:base] : URI.decode_www_form_component(value)
    end

    def apply_attributes(value)
      @attributes = case value
                    when nil then @search_args[:attributes]
                    when '' then []
                    else value.split(',').map { |name| URI.decode_www_form_component(name) }
                    end
    end

    def apply_scope(value)
      case value
      when nil
        @scope = @search_args.fetch(:scope, SearchScope_WholeSubtree)
      else
        @scope = SCOPES[value.downcase] or
          raise InvalidLDAPURLError, "invalid LDAP URL scope: #{value}"
      end
    end

    def apply_filter(value)
      @filter = case value
                when nil
                  @search_args[:filter] || Filter.eq('objectClass', '*')
                when ''
                  raise InvalidLDAPURLError, 'empty LDAP URL filter'
                else
                  URI.decode_www_form_component(value)
                end
    end
  end

  class ReferralFollower
    DEFAULT_MAX_HOPS = 10

    def initialize(args, connection_factory, on_entry = nil)
      @args = args.dup
      @factory = connection_factory
      @on_entry = on_entry
      @config = normalize_config(args[:follow_referrals])
      @report = SearchReport.new
    end

    def run
      root = ReferralEvent.new(:type => :root,
                                :url => root_url(@args), :hop => 0)
      queue = [[@args, root]]
      visited = { effective_identity(@args) => true }

      until queue.empty?
        search_args, source = queue.shift
        followed_referral_results = 0
        result = begin
          search_target(search_args) do |event, value|
            case event
            when :entry
              value.ldap_source = source
              @report.entry(value, source)
              @on_entry&.call(value, source)
              throw :referral_budget_reached if budget_reached?
            when :search_referral
              Array(value).each do |referral_url|
                enqueue(queue, visited, referral_url, source, search_args)
              end
            when :result
              if value.result_code == ResultCodeReferral
                statuses = Array(value.search_referrals).map do |referral_url|
                  enqueue(queue, visited, referral_url, source, search_args)
                end
                followed_referral_results += 1 if statuses.include?(:followed)
              end
            end
          end
        rescue InvalidLDAPURLError
          raise
        rescue StandardError => e
          target_failure(e)
        end

        referral_result = result.result_code == ResultCodeReferral &&
          followed_referral_results.positive?
        if result && !(result.result_code == ResultCodeSuccess || referral_result)
          @report.failure(source, result)
        end

        break if budget_reached?
      end

      SearchAggregateResult.new(@report)
    end

    private

    def normalize_config(config)
      config = config == true ? {} : config.dup
      config[:max_hops] ||= DEFAULT_MAX_HOPS
      config[:result_budget] ||= config[:max_results]
      config[:auth] ||= config[:credentials]
      config
    end

    def search_target(args)
      if @config[:result_budget]
        original_size = args[:size].to_i
        remaining = remaining_budget
        args[:size] = original_size.zero? ? remaining : [original_size, remaining].min
      end
      connection, managed = @factory.call(args)
      result = catch :referral_budget_reached do
        connection.search_with_events(args) do |event, value|
          yield(event, value)
        end
      end
      result || OpenStruct.new(:result_code => ResultCodeSuccess)
    ensure
      connection.close if managed && connection.respond_to?(:close)
    end

    def target_failure(error)
      OpenStruct.new(
        :result_code => ResultCodeOther,
        :error_message => error.message,
        :success? => false
      )
    end

    def enqueue(queue, visited, url, source, parent_args)
      return if budget_reached?

      target = ReferralURL.new(url, parent_args)
      hop = source.hop.to_i + 1
      args = target.target_args
      key = target.identity

      if visited.key?(key)
        @report.skip(url, source, target, :cycle, hop)
        :skipped
      elsif hop > @config[:max_hops]
        @report.skip(url, source, target, :hop_limit, hop)
        :skipped
      elsif !allowed?(target)
        @report.skip(url, source, target, :not_allowed, hop)
        :skipped
      else
        auth = auth_for(target, args)
        if auth == false
          @report.skip(url, source, target, :no_credentials, hop)
          :skipped
        else
          args[:auth] = auth if auth
          visited[key] = true
          event = @report.referral(url, source, target, hop)
          queue << [args, event]
          @report.hop!
          :followed
        end
      end
    rescue InvalidLDAPURLError => e
      @report.skip(url, source, nil, e.message, source.hop.to_i + 1)
      :skipped
    end

    def allowed?(target)
      policy = @config[:allow]
      return false if policy.nil?
      return policy.call(target) if policy.respond_to?(:call)

      Array(policy).any? { |pattern| target_matches?(target, pattern) }
    end

    def target_matches?(target, pattern)
      case pattern
      when Regexp then pattern.match?(target.url)
      when String then target.host == pattern || target.url == pattern
      else pattern.is_a?(Hash) && pattern.all? do |key, value|
        actual = target.public_send(key)
        value.is_a?(Array) ? value.include?(actual) : actual == value
      end
      end
    end

    def auth_for(target, _args)
      auth = @config[:auth]
      if auth.respond_to?(:call)
        auth.call(target)
      elsif auth.is_a?(Hash)
        mapped_auth(auth, target) || auth[:default]
      elsif auth == true
        nil
      end
    end

    def mapped_auth(auth, target)
      mapping = auth[:targets] || auth.reject { |key, _| key == :default }
      mapping.each do |pattern, credentials|
        return credentials if target_matches?(target, pattern)
      end
      nil
    end

    def budget_reached?
      budget = @config[:result_budget]
      budget && @report.result_count >= budget
    end

    def remaining_budget
      @config[:result_budget] - @report.result_count
    end

    def effective_identity(args)
      [args[:host], args[:port], args[:base], args[:scope], args[:filter],
       args[:attributes]].inspect
    end

    def root_url(args)
      scheme = args[:encryption]&.dig(:method) == :simple_tls ? 'ldaps' : 'ldap'
      "#{scheme}://#{args[:host]}:#{args[:port]}/#{args[:base]}"
    end
  end
end
