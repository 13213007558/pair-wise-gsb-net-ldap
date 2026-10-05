require_relative 'test_helper'
require 'ostruct'

class TestReferrals < Test::Unit::TestCase
  class MemoryConnection
    def self.registry
      @registry ||= {}
    end

    def self.reset
      registry.clear
    end

    def self.directory(host, entries: [], search_referrals: [], result_code: Net::LDAP::ResultCodeSuccess)
      registry[host] = new(entries, search_referrals, result_code)
    end

    def self.for_args(args)
      registry[args[:host]]
    end

    attr_reader :searches, :bind_credentials

    def initialize(entries, search_referrals, result_code)
      @entries = entries
      @search_referrals = search_referrals
      @result_code = result_code
      @searches = []
      @bind_credentials = []
    end

    def bind(auth)
      @bind_credentials << auth
      OpenStruct.new(:result_code => Net::LDAP::ResultCodeSuccess, :success? => true)
    end

    def search_with_events(args)
      @searches << args
      limit = args[:size].to_i
      entries = limit.zero? ? @entries : @entries.first(limit)

      entries.each { |entry| yield(:entry, entry) }
      unless @search_referrals.empty?
        yield(:search_referral, @search_referrals)
      end

      result = OpenStruct.new(
        :result_code => @result_code,
        :search_referrals => @search_referrals,
        :success? => @result_code == Net::LDAP::ResultCodeSuccess
      )
      yield(:result, result)
      result
    end

    def close
      @closed = true
    end
  end

  def entry(dn)
    entry = Net::LDAP::Entry.new(dn)
    entry[:cn] = [dn]
    entry
  end

  def build_directories
    MemoryConnection.reset
    MemoryConnection.directory(
      'root.example',
      :entries => [entry('uid=root,dc=example,dc=org')],
      :search_referrals => ['ldap://a.example/dc=example,dc=org?cn?sub?(objectClass=*)']
    )
    MemoryConnection.directory(
      'a.example',
      :entries => [entry('uid=a,dc=example,dc=org')],
      :search_referrals => ['ldap://b.example/dc=example,dc=org?cn?sub?(objectClass=*)']
    )
    MemoryConnection.directory(
      'b.example',
      :entries => [entry('uid=b,dc=example,dc=org')],
      :search_referrals => ['ldap://a.example/dc=example,dc=org?cn?sub?(objectClass=*)']
    )
    MemoryConnection.directory(
      'partial.example',
      :entries => [entry('uid=partial,dc=example,dc=org')],
      :result_code => Net::LDAP::ResultCodeUnavailable
    )
    MemoryConnection.directory(
      'final.example',
      :search_referrals => ['ldap://a.example/dc=example,dc=org?cn?sub?(objectClass=*)'],
      :result_code => Net::LDAP::ResultCodeReferral
    )
  end

  def new_ldap(root_password: nil)
    options = { :host => 'root.example', :base => 'dc=example,dc=org' }
    if root_password
      options[:auth] = {
        :method => :simple,
        :username => 'cn=root',
        :password => root_password
      }
    end
    ldap = Net::LDAP.new(options)
    ldap.define_singleton_method(:referral_connection) do |args|
      [MemoryConnection.for_args(args), false]
    end
    ldap
  end

  def test_follows_cycle_reports_entries_and_skip_reason
    build_directories
    ldap = new_ldap(:root_password => 'root-secret')
    requested_targets = []

    results = ldap.search(
      :attributes => ['cn'],
      :follow_referrals => {
        :allow => %w[a.example b.example],
        :auth => lambda do |target|
          requested_targets << target.host
          { :method => :simple, :username => "cn=#{target.host}", :password => 'target-secret' }
        end
      }
    )

    assert_equal %w[uid=root uid=a uid=b], results.map { |item| item.dn.split(',').first }
    assert_equal ['root.example', 'a.example', 'b.example'],
                 results.map { |item| item.ldap_source.target&.host || 'root.example' }
    assert_equal :cycle, ldap.last_search_report.skipped.first.reason
    assert_equal 'a.example', ldap.last_search_report.skipped.first.target.host
    assert_equal %w[a.example b.example], requested_targets
    a_target = MemoryConnection.for_args(host: 'a.example')
    assert_equal ['target-secret'], a_target.searches.map { |args| args[:auth][:password] }.uniq
    assert_equal ['root-secret'], MemoryConnection.for_args(host: 'root.example').searches.map { |args| args[:auth][:password] }.uniq
  end

  def test_keeps_partial_entries_and_reports_failed_source
    build_directories
    ldap = new_ldap
    ldap.define_singleton_method(:referral_connection) do |args|
      [MemoryConnection.registry.fetch(args[:host]), false]
    end
    ldap.instance_variable_set(:@host, 'partial.example')

    results = ldap.search(
      :follow_referrals => { :allow => [] }
    )

    assert_equal ['uid=partial,dc=example,dc=org'], results.map(&:dn)
    assert_equal Net::LDAP::ResultCodeUnavailable, ldap.get_operation_result.code
    assert_equal 'partial.example', ldap.last_search_report.failures.first.source.url[%r{ldap://([^:/]+)}, 1]
  end

  def test_denied_target_is_reported_and_not_connected
    build_directories
    ldap = new_ldap

    ldap.search(:follow_referrals => { :allow => [] })

    skipped = ldap.last_search_report.skipped.first
    assert_equal :not_allowed, skipped.reason
    assert_equal 'a.example', skipped.target.host
    assert_empty MemoryConnection.for_args(host: 'a.example').searches
  end

  def test_final_referral_result_is_traced_like_search_reference
    build_directories
    ldap = new_ldap
    ldap.instance_variable_set(:@host, 'final.example')

    results = ldap.search(
      :follow_referrals => { :allow => %w[a.example b.example] }
    )

    assert_equal %w[uid=a uid=b], results.map { |item| item.dn.split(',').first }
    assert_empty ldap.last_search_report.failures
    assert_equal :cycle, ldap.last_search_report.skipped.first.reason
  end

  def test_global_result_budget_covers_all_directories
    build_directories
    ldap = new_ldap

    results = ldap.search(
      :follow_referrals => {
        :allow => %w[a.example b.example],
        :result_budget => 2
      }
    )

    assert_equal %w[uid=root uid=a], results.map { |item| item.dn.split(',').first }
    assert_equal 2, ldap.last_search_report.result_count
    assert_empty MemoryConnection.for_args(host: 'b.example').searches
  end

  def test_url_defaults_are_inherited_and_explicit_empty_values_are_distinct
    original = {
      :host => 'root.example',
      :port => 1389,
      :base => 'dc=root',
      :scope => Net::LDAP::SearchScope_WholeSubtree,
      :filter => '(cn=original)',
      :attributes => ['mail', 'cn']
    }

    inherited = Net::LDAP::ReferralURL.new('ldap://a.example/dc=a?', original).target_args
    assert_equal 'dc=a', inherited[:base]
    assert_equal Net::LDAP::SearchScope_WholeSubtree, inherited[:scope]
    assert_equal '(cn=original)', inherited[:filter]
    assert_equal ['mail', 'cn'], inherited[:attributes]

    empty_explicit = Net::LDAP::ReferralURL.new('ldap:///dc=a?', original).target_args
    assert_equal 'root.example', empty_explicit[:host]
    assert_equal 1389, empty_explicit[:port]

    no_attributes = Net::LDAP::ReferralURL.new('ldap://a.example/dc=a?', original)
    assert_equal ['mail', 'cn'], no_attributes.attributes

    explicit_empty_dn = Net::LDAP::ReferralURL.new('ldap://a.example/?uid?sub?(uid=x)', original)
    assert_equal '', explicit_empty_dn.dn

    omitted_dn = Net::LDAP::ReferralURL.new('ldap://a.example?uid?sub?(uid=x)', original)
    assert_equal 'dc=root', omitted_dn.dn

    assert_raise Net::LDAP::InvalidLDAPURLError do
      Net::LDAP::ReferralURL.new('ldap://a.example/dc=a?uid??', original)
    end
    assert_raise Net::LDAP::InvalidLDAPURLError do
      Net::LDAP::ReferralURL.new('ldap://a.example/dc=a?*??', original)
    end
    assert_raise Net::LDAP::InvalidLDAPURLError do
      Net::LDAP::ReferralURL.new('ldap://a.example/dc=a?*?base?', original)
    end
    assert_raise Net::LDAP::InvalidLDAPURLError do
      Net::LDAP::ReferralURL.new('ldap://a.example/dc=a??base?', original)
    end
  end
end
