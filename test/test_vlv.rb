require_relative 'test_helper'

class TestLDAPVLV < Test::Unit::TestCase
  # A fake socket that records every packet written to it and replays a
  # scripted list of (already parsed) BER responses.
  class FakeVLVSocket
    attr_reader :written

    def initialize(responses = [])
      @responses = responses
      @written = []
    end

    def write(packet)
      @written << packet
      packet.length
    end

    def read_ber(*args)
      @responses.shift
    end
  end

  BASE = "ou=People,dc=example,dc=com"
  FILTER = "(objectClass=person)"
  SORT = [["sn", "caseIgnoreOrderingMatch", false]]

  def make_connection(responses = [])
    @socket = FakeVLVSocket.new(responses)
    Net::LDAP::Connection.new(:socket => @socket)
  end

  def make_search_entry(msgid, dn, attrs = {})
    ber = Net::BER::BerIdentifiedArray.new([dn, attrs.map { |k, v| [k.to_s, Array(v)] }])
    ber.ber_identifier = Net::LDAP::PDU::SearchReturnedData
    [msgid, ber]
  end

  def make_vlv_result(msgid, options = {})
    options = {
      :result_code => Net::LDAP::ResultCodeSuccess,
      :sort_code   => Net::LDAP::ResultCodeSuccess,
      :vlv_code    => Net::LDAP::ResultCodeSuccess,
      :target      => 100,
      :count       => 50_000,
      :context_id  => "vlv-ctx-1",
      :include_vlv => true,
    }.merge(options)

    result = Net::BER::BerIdentifiedArray.new([options[:result_code], "", ""])
    result.ber_identifier = Net::LDAP::PDU::SearchResult

    controls = []
    sort_value = [options[:sort_code].to_ber_enumerated].to_ber_sequence
    controls << [Net::LDAP::LDAPControls::SORT_RESPONSE, false, sort_value]
    if options[:include_vlv]
      vlv_value = [
        options[:target].to_ber,
        options[:count].to_ber,
        options[:vlv_code].to_ber_enumerated,
      ]
      vlv_value << options[:context_id].to_ber if options[:context_id]
      controls << [Net::LDAP::LDAPControls::VLV_RESPONSE, false, vlv_value.to_ber_sequence]
    end

    [msgid, result, controls]
  end

  # Decodes the last packet written to the fake socket into
  # [message_id, request, controls].
  def last_request
    @socket.written.last.read_ber(Net::LDAP::AsnSyntax)
  end

  def control_value(controls, oid)
    control = controls.find { |c| c[0] == oid }
    control && control[2]
  end

  def vlv_request_values(controls)
    value = control_value(controls, Net::LDAP::LDAPControls::VLV_REQUEST)
    value && value.read_ber(Net::LDAP::AsnSyntax)
  end

  def sort_request_keys(controls)
    value = control_value(controls, Net::LDAP::LDAPControls::SORT_REQUEST)
    value && value.read_ber
  end

  def search_args(extra = {})
    {
      :base          => BASE,
      :filter        => FILTER,
      :sort_controls => SORT,
      :vlv           => { :before_count => 2, :after_count => 2, :offset => 100, :content_count => 0 },
    }.merge(extra)
  end

  def test_encode_vlv_controls_by_offset
    conn = make_connection
    ber = conn.encode_vlv_controls(:before_count => 5, :after_count => 4,
                                   :offset => 101, :content_count => 0)

    expected_value = "\x30\x0e".b + 5.to_ber + 4.to_ber +
                     "\xa0\x06".b + 101.to_ber + 0.to_ber
    expected = [
      Net::LDAP::LDAPControls::VLV_REQUEST.to_ber,
      false.to_ber,
      expected_value.to_ber,
    ].to_ber_sequence
    assert_equal expected, ber

    oid, criticality, value = ber.read_ber
    assert_equal Net::LDAP::LDAPControls::VLV_REQUEST, oid
    assert_equal false, criticality

    before_count, after_count, target = value.read_ber(Net::LDAP::AsnSyntax)
    assert_equal 5, before_count
    assert_equal 4, after_count
    assert_equal 0xa0, target.ber_identifier
    assert_equal [101, 0], target
  end

  def test_encode_vlv_controls_by_assertion
    conn = make_connection
    ber = conn.encode_vlv_controls(:before_count => 5, :after_count => 4,
                                   :assertion => "smith")

    _oid, _criticality, value = ber.read_ber
    before_count, after_count, target = value.read_ber(Net::LDAP::AsnSyntax)
    assert_equal 5, before_count
    assert_equal 4, after_count
    assert_equal 0x81, target.ber_identifier
    assert_equal "smith", target
  end

  def test_encode_vlv_controls_with_context_id
    conn = make_connection
    ber = conn.encode_vlv_controls(:before_count => 1, :after_count => 1,
                                   :offset => 10, :content_count => 100,
                                   :context_id => "abc")

    _oid, _criticality, value = ber.read_ber
    values = value.read_ber(Net::LDAP::AsnSyntax)
    assert_equal 4, values.length
    assert_equal "abc", values[3]
  end

  def test_encode_sort_controls_does_not_modify_caller_definitions
    conn = make_connection
    sort = [["sn", "caseIgnoreOrderingMatch", true], ["givenname"]]

    ber1 = conn.encode_sort_controls(sort)
    ber2 = conn.encode_sort_controls(sort)

    assert_equal ber1, ber2
    assert_equal [["sn", "caseIgnoreOrderingMatch", true], ["givenname"]], sort
  end

  def test_search_vlv_by_offset_returns_window
    conn = make_connection([
      make_search_entry(1, "uid=user99,#{BASE}", :uid => ["user99"], :sn => ["Allen"]),
      make_search_entry(1, "uid=user100,#{BASE}", :uid => ["user100"], :sn => ["Alston"]),
      make_vlv_result(1, :target => 100, :count => 50_000, :context_id => "ctx-1"),
    ])

    entries = []
    result = conn.search_vlv(search_args) { |entry| entries << entry }

    assert_equal :success, result.status
    assert_equal Net::LDAP::ResultCodeSuccess, result.result_code
    assert_equal 100, result.target_position
    assert_equal 50_000, result.content_count
    assert_equal "ctx-1", result.context_id
    assert_equal 2, result.before_count
    assert_equal 2, result.after_count
    assert_equal 0, result.sort_result_code
    assert_equal 0, result.vlv_result_code
    assert_equal ["uid=user99,#{BASE}", "uid=user100,#{BASE}"], entries.map(&:dn)

    _msgid, _request, controls = last_request
    assert_equal ["sn"], sort_request_keys(controls).map { |key| key[0] }

    before_count, after_count, target = vlv_request_values(controls)
    assert_equal 2, before_count
    assert_equal 2, after_count
    assert_equal [100, 0], target
  end

  def test_search_vlv_by_assertion
    conn = make_connection([
      make_vlv_result(1, :target => 87, :count => 50_000, :context_id => nil),
    ])

    result = conn.search_vlv(search_args(:vlv => { :before_count => 4, :after_count => 5,
                                                   :assertion => "smith" }))

    assert_equal :success, result.status
    assert_equal 87, result.target_position
    assert_nil result.context_id

    _msgid, _request, controls = last_request
    before_count, after_count, target = vlv_request_values(controls)
    assert_equal 4, before_count
    assert_equal 5, after_count
    assert_equal 0x81, target.ber_identifier
    assert_equal "smith", target
  end

  def test_search_vlv_requires_sort_controls
    conn = make_connection
    assert_raise ArgumentError do
      conn.search_vlv(:base => BASE, :vlv => { :offset => 1 })
    end
  end

  def test_search_vlv_context_reused_while_window_moves
    conn = make_connection([
      make_vlv_result(1, :target => 100, :context_id => "ctx-1"),
      make_vlv_result(2, :target => 110, :context_id => "ctx-1"),
    ])
    context = {}

    r1 = conn.search_vlv(search_args(:vlv_context => context))
    assert_equal "ctx-1", r1.context_id
    assert_equal "ctx-1", context[:context_id]

    # first request carries no context id
    _msgid, _request, controls = last_request
    assert_equal 3, vlv_request_values(controls).length

    r2 = conn.search_vlv(search_args(:vlv_context => context,
                                     :vlv => { :before_count => 2, :after_count => 2,
                                               :offset => 110, :content_count => r1.content_count }))
    assert_equal "ctx-1", r2.context_id

    # second request resumes the server-side context
    _msgid, _request, controls = last_request
    values = vlv_request_values(controls)
    assert_equal 4, values.length
    assert_equal "ctx-1", values[3]
    assert_equal [110, 50_000], values[2].to_a
  end

  def test_search_vlv_context_not_reused_when_filter_changes
    conn = make_connection([
      make_vlv_result(1, :context_id => "ctx-1"),
      make_vlv_result(2, :context_id => "ctx-2"),
    ])
    context = {}

    conn.search_vlv(search_args(:vlv_context => context))
    conn.search_vlv(search_args(:vlv_context => context, :filter => "(objectClass=inetOrgPerson)"))

    _msgid, _request, controls = last_request
    assert_equal 3, vlv_request_values(controls).length
  end

  def test_search_vlv_context_not_reused_when_sort_keys_change
    conn = make_connection([
      make_vlv_result(1, :context_id => "ctx-1"),
      make_vlv_result(2, :context_id => "ctx-2"),
    ])
    context = {}

    conn.search_vlv(search_args(:vlv_context => context))
    conn.search_vlv(search_args(:vlv_context => context, :sort_controls => ["cn"]))

    _msgid, _request, controls = last_request
    assert_equal 3, vlv_request_values(controls).length
  end

  def test_search_vlv_context_not_reused_across_connections
    conn1 = make_connection([make_vlv_result(1, :context_id => "ctx-1")])
    context = {}
    conn1.search_vlv(search_args(:vlv_context => context))
    assert_equal "ctx-1", context[:context_id]

    conn2 = make_connection([make_vlv_result(1, :context_id => "ctx-9")])
    conn2.search_vlv(search_args(:vlv_context => context))

    _msgid, _request, controls = last_request
    assert_equal 3, vlv_request_values(controls).length
    assert_equal "ctx-9", context[:context_id]
  end

  def test_search_vlv_sort_failure_is_preserved
    conn = make_connection([
      make_vlv_result(1, :sort_code => Net::LDAP::ResultCodeNoSuchAttribute),
    ])

    result = conn.search_vlv(search_args)

    assert_equal :failure, result.status
    assert_equal Net::LDAP::ResultCodeNoSuchAttribute, result.result_code
    assert_equal Net::LDAP::ResultCodeNoSuchAttribute, result.sort_result_code
    assert_equal Net::LDAP::ResultCodeSuccess, result.vlv_result_code
    assert_nil result.target_position
    assert_match(/sort control failed/, result.error_message)
  end

  def test_search_vlv_vlv_failure_is_preserved
    conn = make_connection([
      make_vlv_result(1, :vlv_code => 61), # offsetRangeError
    ])

    result = conn.search_vlv(search_args)

    assert_equal :failure, result.status
    assert_equal 61, result.result_code
    assert_equal 61, result.vlv_result_code
    assert_equal Net::LDAP::ResultCodeSuccess, result.sort_result_code
    assert_nil result.target_position
    assert_match(/VLV control failed/, result.error_message)
  end

  def test_search_vlv_missing_vlv_response_control_is_not_an_empty_window
    conn = make_connection([
      make_vlv_result(1, :include_vlv => false),
    ])

    result = conn.search_vlv(search_args)

    assert_equal :failure, result.status
    assert_equal Net::LDAP::ResultCodeUnavailableCriticalExtension, result.result_code
    assert_nil result.target_position
    assert_nil result.context_id
  end

  def test_search_vlv_search_failure_is_preserved
    conn = make_connection([
      make_vlv_result(1, :result_code => Net::LDAP::ResultCodeUnwillingToPerform),
    ])

    result = conn.search_vlv(search_args)

    assert_equal :failure, result.status
    assert_equal Net::LDAP::ResultCodeUnwillingToPerform, result.result_code
  end
end

class TestLDAPVLVTopLevel < Test::Unit::TestCase
  # A fake connection standing in at the Net::LDAP level.
  class FakeConnection
    attr_reader :search_args

    def initialize(entries, vlv_result)
      @entries = entries
      @vlv_result = vlv_result
    end

    def bind(*_args)
      OpenStruct.new(:result_code => Net::LDAP::ResultCodeSuccess)
    end

    def socket; end

    def close; end

    def search_vlv(args)
      @search_args = args
      @entries.each { |entry| yield entry }
      @vlv_result
    end
  end

  def test_search_vlv_returns_entries_and_operation_result
    entries = [
      Net::LDAP::Entry.new("uid=user100,ou=People,dc=example,dc=com"),
      Net::LDAP::Entry.new("uid=user101,ou=People,dc=example,dc=com"),
    ]
    vlv_result = OpenStruct.new(
      :result_code      => Net::LDAP::ResultCodeSuccess,
      :error_message    => "",
      :status           => :success,
      :sort_result_code => 0,
      :vlv_result_code  => 0,
      :target_position  => 100,
      :content_count    => 50_000,
      :context_id       => "ctx-1",
      :before_count     => 0,
      :after_count      => 1,
    )
    conn = FakeConnection.new(entries, vlv_result)
    flexmock(Net::LDAP::Connection).should_receive(:new).and_return(conn)

    ldap = Net::LDAP.new(:host => "test.mocked.com", :base => "ou=People,dc=example,dc=com")
    yielded = []
    result = ldap.search_vlv(:filter => "(objectClass=person)",
                             :sort_controls => ["sn"],
                             :vlv => { :before_count => 0, :after_count => 1, :offset => 100 }) do |entry|
      yielded << entry
    end

    assert_equal entries, yielded
    assert_equal entries, result.entries
    assert_equal 100, result.target_position
    assert_equal 50_000, result.content_count
    assert_equal "ctx-1", result.context_id
    assert_equal "ou=People,dc=example,dc=com", conn.search_args[:base]

    op_result = ldap.get_operation_result
    assert_equal Net::LDAP::ResultCodeSuccess, op_result.code
  end
end
