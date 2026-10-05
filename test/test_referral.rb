# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'
require 'socket'

class TestLDAPReferral < Test::Unit::TestCase
  class MemorySocket
    def self.registry
      @registry ||= {}
    end

    def self.register(name, directory)
      registry[name] = directory
    end

    def self.new(host, port, socket_opts = {})
      client, server = Socket.pair(:UNIX, :STREAM, 0)
      Thread.new(registry.fetch(host), server) do |directory, socket|
        directory.serve(socket)
      ensure
        socket.close unless socket.closed?
      end
      client
    end
  end

  class MemoryDirectory
    attr_reader :bind_passwords

    def initialize(name, entries:, referrals:, result_code: Net::LDAP::ResultCodeSuccess,
                   result_message: '', bind_password: nil)
      @name = name
      @entries = entries
      @referrals = referrals
      @result_code = result_code
      @result_message = result_message
      @bind_password = bind_password
    end

    def serve(socket)
      pdu = socket.read_ber(Net::LDAP::AsnSyntax)
      bind_pdu = Net::LDAP::PDU.new(pdu)
      unless valid_bind?(bind_pdu)
        socket.write(result(bind_pdu.message_id, Net::LDAP::PDU::BindResult,
                            Net::LDAP::ResultCodeInvalidCredentials, 'invalid credentials'))
        return
      end

      socket.write(result(bind_pdu.message_id, Net::LDAP::PDU::BindResult,
                          Net::LDAP::ResultCodeSuccess, ''))

      search = Net::LDAP::PDU.new(socket.read_ber(Net::LDAP::AsnSyntax))
      @entries.each do |dn, attributes|
        socket.write(entry(search.message_id, dn, attributes))
      end
      @referrals.each { |uri| socket.write(reference(search.message_id, uri)) }
      socket.write(result(search.message_id, Net::LDAP::PDU::SearchResult,
                          @result_code, @result_message, @referrals))
    end

    private

    def valid_bind?(pdu)
      return pdu.result_code == Net::LDAP::ResultCodeSuccess if pdu.app_tag != Net::LDAP::PDU::BindRequest

      auth = pdu.bind_parameters.authentication
      return @bind_password.nil? if auth.is_a?(Net::BER::BerIdentifiedNull)
      auth.to_s == @bind_password
    end

    def entry(message_id, dn, attributes)
      attrs = attributes.map do |name, values|
        [name.to_s.to_ber, Array(values).map(&:to_ber).to_ber_set].to_ber_sequence
      end
      body = [dn.to_ber, attrs.to_ber_sequence].to_ber_appsequence(Net::LDAP::PDU::SearchReturnedData)
      [message_id.to_ber, body].to_ber_sequence
    end

    def reference(message_id, uri)
      body = [uri.to_ber].to_ber_appsequence(Net::LDAP::PDU::SearchResultReferral)
      [message_id.to_ber, body].to_ber_sequence
    end

    def result(message_id, app_tag, code, message, uris = nil)
      body_parts = [code.to_ber_enumerated, ''.to_ber, message.to_ber]
      body_parts << uris.map(&:to_ber).to_ber_contextspecific(3) if uris && !uris.empty?
      body = body_parts.to_ber_appsequence(app_tag)
      [message_id.to_ber, body].to_ber_sequence
    end
  end

  def setup
    @base = 'dc=example,dc=org'
    @a_url = "ldap://a.example:389/#{@base}"
    @b_url = "ldap://b.example:389/#{@base}"
    @c_url = "ldap://c.example:389/#{@base}"

    register_directory('a.example', entries: { 'uid=a,' + @base => { cn: 'alpha' } },
                                   referrals: [@b_url, @c_url], bind_password: 'root-secret')
    register_directory('b.example', entries: { 'uid=b,' + @base => { cn: 'bravo' } },
                                   referrals: [@a_url], bind_password: 'b-secret')
    register_directory('c.example', entries: { 'uid=c,' + @base => { cn: 'charlie' } },
                                   referrals: [], result_code: Net::LDAP::ResultCodeUnavailable,
                                   result_message: 'partial failure', bind_password: 'c-secret')
  end

  def register_directory(host, options)
    MemorySocket.register(host, MemoryDirectory.new(host, **options))
  end

  def client(options = {})
    Net::LDAP.new({
      host: 'a.example',
      port: 389,
      auth: { method: :simple, username: 'cn=root', password: 'root-secret' },
      socket_class: MemorySocket,
      force_no_page: true,
      base: @base,
    }.merge(options))
  end

  def policy
    lambda do |target|
      if target[:host] == 'b.example'
        { allow: true, auth: { method: :simple, username: 'cn=b', password: 'b-secret' } }
      elsif target[:host] == 'c.example'
        { allow: true, auth: { method: :simple, username: 'cn=c', password: 'c-secret' } }
      else
        { allow: false, reason: :target_not_allowed }
      end
    end
  end

  def test_follows_referrals_with_global_trace_and_partial_failure
    events = []
    streamed = []
    search_client = client
    entries = search_client.search(
      follow_referrals: true,
      referral_policy: policy,
      max_referral_hops: 3,
      on_referral_event: ->(event) { events << event },
    ) { |entry| streamed << entry.cn.first }

    assert_equal %w[alpha bravo charlie], entries.map { |entry| entry.cn.first }
    assert_equal %w[alpha bravo charlie], streamed
    assert_equal [0, 1, 1], entries.map { |entry| entry.ldap_source[:hop] }
    assert_equal 'a.example', entries.first.ldap_source[:host]
    assert_equal 'b.example', entries[1].ldap_source[:host]
    assert_equal 'c.example', entries.last.ldap_source[:host]

    result = search_client.get_operation_result
    assert_equal 0, result.code
    failures = result.referral_trace[:failures]
    assert_equal ['c.example'], failures.map { |event| event[:url] }.map { |url| URI(url).host }
    assert_equal Net::LDAP::ResultCodeUnavailable, failures.first[:result_code]
    assert_equal 'partial failure', failures.first[:error_message]

    skipped = result.referral_trace[:skipped]
    assert_equal [:referral_cycle], skipped.map { |event| event[:reason] }
    assert_equal @a_url, skipped.first[:raw_uri]
    assert events.any? { |event| event[:type] == :failure && event[:error_message] == 'partial failure' }
    assert events.any? { |event| event[:type] == :skipped && event[:reason] == :referral_cycle }
  end

  def test_does_not_transfer_root_password_and_reports_not_allowed
    denied_url = 'ldap://denied.example:389/' + @base
    register_directory('a-denied.example', entries: {}, referrals: [denied_url],
                                       bind_password: 'root-secret')
    observed_targets = []
    observing_policy = lambda do |target|
      observed_targets << target
      { allow: false, reason: :not_allowed }
    end

    ldap = client(host: 'a-denied.example')
    entries = ldap.search(follow_referrals: true, referral_policy: observing_policy)

    assert_empty entries
    skipped = ldap.get_operation_result.referral_trace[:skipped]
    assert_equal [:not_allowed], skipped.map { |event| event[:reason] }
    assert_equal denied_url, skipped.first[:raw_uri]
    refute observed_targets.first.key?(:auth)
    refute_equal 'root-secret', observed_targets.first[:raw_uri]
  end

  def test_referrals_are_not_chased_without_opt_in
    entries = client.search

    assert_equal ['alpha'], entries.map { |entry| entry.cn.first }
    skipped = client.get_operation_result.referral_trace
    assert_nil skipped
  end

  def test_global_result_budget_applies_across_referral_hops
    budget_client = client
    entries = budget_client.search(
      follow_referrals: true,
      referral_policy: policy,
      max_referral_hops: 3,
      size: 2,
    )

    assert_equal %w[alpha bravo], entries.map { |entry| entry.cn.first }
    skipped = budget_client.get_operation_result.referral_trace[:skipped]
    assert_include skipped.map { |event| event[:reason] }, :result_budget_exceeded
  end

  def test_ldap_url_inheritance_and_explicit_empty_attributes
    inherited = {
      base: 'dc=inherited',
      scope: Net::LDAP::SearchScope_WholeSubtree,
      filter: Net::LDAP::Filter.eq('uid', 'user'),
      attributes: %w[cn mail],
      attributes_given: true,
      hop: 0,
      source_url: 'ldap://root/',
    }

    inherited_target = Net::LDAP::Referral::URL.parse('ldap://target:389', inherited)
    assert_equal 'dc=inherited', inherited_target.base
    assert_equal Net::LDAP::SearchScope_WholeSubtree, inherited_target.scope
    assert_equal '(uid=user)', inherited_target.filter.to_s
    assert_equal %w[cn mail], inherited_target.attributes

    empty_target = Net::LDAP::Referral::URL.parse('ldap://target:389/dc=explicit??', inherited)
    assert_equal 'dc=explicit', empty_target.base
    assert_equal Net::LDAP::SearchScope_BaseObject, empty_target.scope
    assert_equal [], empty_target.attributes
    assert_equal true, empty_target.attributes_given

    base_target = Net::LDAP::Referral::URL.parse('ldap://target:389/dc=base?cn?base?(objectClass=*)', inherited)
    assert_equal Net::LDAP::SearchScope_BaseObject, base_target.scope
    assert_equal %w[cn], base_target.attributes

    default_filter_target = Net::LDAP::Referral::URL.parse('ldap://target:389/dc=base?cn?base?', inherited)
    assert_equal '(objectClass=*)', default_filter_target.filter.to_s

    empty_dn_target = Net::LDAP::Referral::URL.parse('ldap://target:389/', inherited)
    assert_equal '', empty_dn_target.base
  end
end
