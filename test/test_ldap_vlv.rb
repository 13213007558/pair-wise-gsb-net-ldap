# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'

class TestLDAPVLV < Test::Unit::TestCase
  # Fake socket for testing: returns queued BER packets on #read_ber and
  # captures everything written by the connection.
  class FakeSocket
    attr_reader :written

    def initialize
      @read_queue = []
      @written = []
    end

    def queue(packet)
      @read_queue << packet
    end

    def write(packet)
      @written << packet
      packet.length
    end

    def read_ber(syntax = nil)
      @read_queue.shift.read_ber(syntax)
    end
  end

  def setup
    @socket = FakeSocket.new
    @connection = Net::LDAP::Connection.new({})
    @connection.instance_variable_set(:@conn, @socket)
  end

  # BER-encodes a SearchResultEntry PDU for the fake server.
  def encode_entry(message_id, dn, attributes)
    attrs = attributes.map do |name, values|
      [name.to_ber, values.map(&:to_ber).to_ber_set].to_ber_sequence
    end.to_ber_sequence
    entry = [dn.to_ber, attrs].to_ber_appsequence(Net::LDAP::PDU::SearchReturnedData)
    [message_id.to_ber, entry].to_ber_sequence
  end

  # BER-encodes a SearchResultDone PDU, optionally carrying sort and VLV
  # response controls, for the fake server.
  def encode_done(message_id, result_code: 0, sort_result: nil, vlv: nil)
    controls = []
    if sort_result
      value = [sort_result.to_ber_enumerated].to_ber_sequence
      controls << [
        Net::LDAP::LDAPControls::SORT_RESPONSE.to_ber,
        false.to_ber,
        value.to_ber,
      ].to_ber_sequence
    end
    if vlv
      target_position, content_count, vlv_result, context_id = vlv
      value = [
        target_position.to_ber,
        content_count.to_ber,
        vlv_result.to_ber_enumerated,
      ]
      value << context_id.to_ber if context_id
      controls << [
        Net::LDAP::LDAPControls::VLV_RESPONSE.to_ber,
        false.to_ber,
        value.to_ber_sequence.to_ber,
      ].to_ber_sequence
    end

    result = [
      result_code.to_ber_enumerated,
      "".to_ber,
      "".to_ber,
    ].to_ber_appsequence(Net::LDAP::PDU::SearchResult)
    packet = [message_id.to_ber, result]
    packet << controls.to_ber_contextspecific(0) unless controls.empty?
    packet.to_ber_sequence
  end

  # Parses a packet written by the connection into [message_id, controls],
  # where controls is a list of [oid, criticality, value] tuples.
  def parse_written(packet)
    message_id, _request, controls = packet.read_ber(Net::LDAP::AsnSyntax)
    [message_id, controls || []]
  end

  def control_value(controls, oid)
    control = controls.find { |c| c[0] == oid }
    control && control[2]
  end

  def vlv_args(overrides = {})
    {
      :base => "ou=people,dc=example,dc=com",
      :filter => "(objectClass=person)",
      :sort_controls => ["sn"],
      :before_count => 3,
      :after_count => 6,
      :offset => 101,
      :content_count => 0,
    }.merge(overrides)
  end

  def test_encode_sort_controls_does_not_modify_caller_arguments
    sort_definitions = [["cn", "matchingRule", true], ["sn"], "givenname"]
    snapshot = sort_definitions.map { |c| Array(c).dup }

    @connection.encode_sort_controls(sort_definitions)

    assert_equal snapshot, sort_definitions.map { |c| Array(c).dup }
  end

  def test_encode_sort_controls_ber
    ber = @connection.encode_sort_controls([["cn", "matchingRule", true], "sn"])

    oid, criticality, value = ber.read_ber
    assert_equal Net::LDAP::LDAPControls::SORT_REQUEST, oid
    assert_equal false, criticality
    assert_equal [["cn", "matchingRule", true], ["sn", "", false]], value.read_ber
  end

  def test_encode_vlv_controls_byoffset
    ber = @connection.encode_vlv_controls(
      :before_count => 3, :after_count => 6,
      :offset => 101, :content_count => 5000)

    oid, criticality, value = ber.read_ber
    assert_equal Net::LDAP::LDAPControls::VLV_REQUEST, oid
    assert_equal false, criticality
    # byoffset is the constructed context-specific tag [0]
    assert_include value, "\xA0\x07\x02\x01\x65\x02\x02\x13\x88".b
    before_count, after_count, target = value.read_ber(Net::LDAP::AsnSyntax)
    assert_equal 3, before_count
    assert_equal 6, after_count
    assert_equal [101, 5000], target
  end

  def test_encode_vlv_controls_greater_or_equal
    ber = @connection.encode_vlv_controls(
      :before_count => 0, :after_count => 9,
      :assertion_value => "smith")

    _oid, _criticality, value = ber.read_ber
    # greaterOrEqual is the primitive context-specific tag [1]
    assert_include value, "\x81\x05smith".b
    before_count, after_count, target = value.read_ber(Net::LDAP::AsnSyntax)
    assert_equal 0, before_count
    assert_equal 9, after_count
    assert_equal "smith", target
  end

  def test_encode_vlv_controls_with_context_id
    context_id = "\x00\xFFctx".b
    ber = @connection.encode_vlv_controls(
      :before_count => 1, :after_count => 1,
      :offset => 5, :content_count => 100,
      :context_id => context_id)

    _oid, _criticality, value = ber.read_ber
    # binary context IDs must survive the encoding unmodified
    assert_include value, "\x04\x05\x00\xFFctx".b
    _before, _after, _target, encoded_context = value.read_ber(Net::LDAP::AsnSyntax)
    assert_equal context_id, encoded_context
  end

  def test_search_virtual_list_view_byoffset
    @socket.queue encode_entry(1, "cn=smith,ou=people,dc=example,dc=com",
      "cn" => ["Smith"], "sn" => ["Smith"])
    @socket.queue encode_done(1, :sort_result => 0, :vlv => [101, 500_000, 0, "ctx-1"])

    entries = []
    pdu = @connection.search_virtual_list_view(vlv_args) do |entry|
      entries << entry
    end

    assert_equal Net::LDAP::ResultCodeSuccess, pdu.result_code
    assert_equal 1, entries.size
    assert_equal "cn=smith,ou=people,dc=example,dc=com", entries.first.dn

    message_id, controls = parse_written(@socket.written.first)
    assert_equal 1, message_id
    assert control_value(controls, Net::LDAP::LDAPControls::SORT_REQUEST)
    vlv_value = control_value(controls, Net::LDAP::LDAPControls::VLV_REQUEST)
    assert_equal [3, 6, [101, 0]], vlv_value.read_ber(Net::LDAP::AsnSyntax)
  end

  def test_search_virtual_list_view_assertion_value
    @socket.queue encode_done(1, :sort_result => 0, :vlv => [42, 500_000, 0, nil])

    @connection.search_virtual_list_view(
      vlv_args(:assertion_value => "smith", :offset => nil, :content_count => nil))

    _message_id, controls = parse_written(@socket.written.first)
    vlv_value = control_value(controls, Net::LDAP::LDAPControls::VLV_REQUEST)
    assert_equal [3, 6, "smith"], vlv_value.read_ber(Net::LDAP::AsnSyntax)
  end

  def test_search_virtual_list_view_requires_exactly_one_target
    assert_raise(ArgumentError) do
      @connection.search_virtual_list_view(vlv_args(:offset => nil, :content_count => nil))
    end
    assert_raise(ArgumentError) do
      @connection.search_virtual_list_view(vlv_args(:assertion_value => "smith"))
    end
  end

  def test_search_virtual_list_view_requires_sort_controls
    assert_raise(ArgumentError) do
      @connection.search_virtual_list_view(vlv_args(:sort_controls => nil))
    end
  end

  def test_search_virtual_list_view_sort_failure_preserves_result_code
    # the server reports a sort error and no VLV control at all
    @socket.queue encode_done(1, :sort_result => Net::LDAP::ResultCodeNoSuchAttribute)

    pdu = @connection.search_virtual_list_view(vlv_args)

    assert_equal Net::LDAP::ResultCodeNoSuchAttribute, pdu.result_code
  end

  def test_search_virtual_list_view_vlv_failure_preserves_result_code
    @socket.queue encode_done(1,
      :sort_result => 0,
      :vlv => [0, 0, Net::LDAP::ResultCodeOffsetRangeError, nil])

    pdu = @connection.search_virtual_list_view(vlv_args)

    assert_equal Net::LDAP::ResultCodeOffsetRangeError, pdu.result_code
  end

  def test_search_virtual_list_view_missing_controls_is_not_success
    @socket.queue encode_done(1)

    assert_raise(Net::LDAP::ResponseMissingOrInvalidError) do
      @connection.search_virtual_list_view(vlv_args)
    end
  end

  def test_search_virtual_list_view_missing_vlv_control_is_not_success
    @socket.queue encode_done(1, :sort_result => 0)

    assert_raise(Net::LDAP::ResponseMissingOrInvalidError) do
      @connection.search_virtual_list_view(vlv_args)
    end
  end

  def test_window_movement_reuses_server_context
    ldap = Net::LDAP.new(:host => "test.example", :base => "ou=people,dc=example,dc=com")
    ldap.connection = @connection

    @socket.queue encode_entry(1, "cn=smith,ou=people,dc=example,dc=com", "sn" => ["Smith"])
    @socket.queue encode_done(1, :sort_result => 0, :vlv => [101, 500_000, 0, "ctx-1"])

    result = ldap.search_virtual_list_view(vlv_args(:base => nil))

    assert_equal 101, result.target_position
    assert_equal 500_000, result.content_count
    assert_equal ["cn=smith,ou=people,dc=example,dc=com"], result.entries.map(&:dn)
    assert_equal "ctx-1", result.context.context_id

    # move the window ten entries forward, reusing the server context
    @socket.queue encode_entry(2, "cn=smyth,ou=people,dc=example,dc=com", "sn" => ["Smyth"])
    @socket.queue encode_done(2, :sort_result => 0, :vlv => [111, 500_000, 0, "ctx-2"])

    result = ldap.search_virtual_list_view(vlv_args(
      :base => nil,
      :offset => result.target_position + 10,
      :content_count => result.content_count,
      :context => result.context))

    assert_equal 111, result.target_position
    assert_equal "ctx-2", result.context.context_id

    _message_id, controls = parse_written(@socket.written[1])
    vlv_value = control_value(controls, Net::LDAP::LDAPControls::VLV_REQUEST)
    assert_equal [3, 6, [111, 500_000], "ctx-1"], vlv_value.read_ber(Net::LDAP::AsnSyntax)
  end

  def test_context_is_rejected_for_different_filter
    ldap = Net::LDAP.new(:host => "test.example", :base => "ou=people,dc=example,dc=com")
    ldap.connection = @connection

    @socket.queue encode_done(1, :sort_result => 0, :vlv => [101, 500_000, 0, "ctx-1"])
    result = ldap.search_virtual_list_view(vlv_args(:base => nil))

    assert_raise(ArgumentError) do
      ldap.search_virtual_list_view(vlv_args(
        :base => nil, :filter => "(objectClass=inetOrgPerson)",
        :context => result.context))
    end
  end

  def test_context_is_rejected_for_different_sort_keys
    ldap = Net::LDAP.new(:host => "test.example", :base => "ou=people,dc=example,dc=com")
    ldap.connection = @connection

    @socket.queue encode_done(1, :sort_result => 0, :vlv => [101, 500_000, 0, "ctx-1"])
    result = ldap.search_virtual_list_view(vlv_args(:base => nil))

    assert_raise(ArgumentError) do
      ldap.search_virtual_list_view(vlv_args(
        :base => nil, :sort_controls => ["cn"],
        :context => result.context))
    end
  end

  def test_context_is_rejected_for_different_connection
    ldap = Net::LDAP.new(:host => "test.example", :base => "ou=people,dc=example,dc=com")
    ldap.connection = @connection

    @socket.queue encode_done(1, :sort_result => 0, :vlv => [101, 500_000, 0, "ctx-1"])
    result = ldap.search_virtual_list_view(vlv_args(:base => nil))

    other_ldap = Net::LDAP.new(:host => "test.example", :base => "ou=people,dc=example,dc=com")
    other_ldap.connection = Net::LDAP::Connection.new({})

    assert_raise(ArgumentError) do
      other_ldap.search_virtual_list_view(vlv_args(
        :base => nil, :context => result.context))
    end
  end

  def test_failed_vlv_search_returns_nil_and_preserves_result
    ldap = Net::LDAP.new(:host => "test.example", :base => "ou=people,dc=example,dc=com")
    ldap.connection = @connection

    @socket.queue encode_done(1,
      :sort_result => 0,
      :vlv => [0, 0, Net::LDAP::ResultCodeOffsetRangeError, nil])

    assert_nil ldap.search_virtual_list_view(vlv_args(:base => nil))
    assert_equal Net::LDAP::ResultCodeOffsetRangeError, ldap.get_operation_result.code
    assert_equal "Offset Range Error", ldap.get_operation_result.message
  end
end
