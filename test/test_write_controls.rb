require_relative 'test_helper'

class TestWriteControls < Test::Unit::TestCase
  ASSERTION_OID = Net::LDAP::LDAPControls::ASSERTION
  PRE_READ_OID = Net::LDAP::LDAPControls::PRE_READ
  POST_READ_OID = Net::LDAP::LDAPControls::POST_READ

  DN = 'cn=test,dc=example,dc=com'.freeze

  # Socket that records every write packet and serves canned or dynamically
  # generated, real-BER responses.
  class FakeWire
    attr_reader :packets

    def initialize(handler = nil, &block)
      @handler = handler || block
      @packets = []
      @queue = []
    end

    def write(packet)
      @packets << packet
      if @handler.respond_to?(:call)
        @queue << @handler.call(parse_packet(packet))
      else
        @queue << @handler
      end
      packet.bytesize
    end

    def read_ber(*)
      @queue.shift
    end

    def close; end

    # Parses message id and controls even when the application value is
    # primitive (e.g. DelRequest, APPLICATION 10) which AsnSyntax does not
    # know how to decode.
    def parse_packet(packet)
      io = StringIO.new(packet)
      io.getbyte # outer SEQUENCE tag
      io.send(:read_ber_length)
      message_id = io.read_ber(Net::LDAP::AsnSyntax)
      app_tag = io.getbyte
      length = io.send(:read_ber_length)
      io.read(length)
      controls = io.read_ber(Net::LDAP::AsnSyntax)
      app = Net::BER::BerIdentifiedArray.new([])
      app.ber_identifier = app_tag
      message = [message_id, app]
      message << controls if controls
      message
    end
  end

  class StaticWire
    def initialize(response)
      @response = response
    end

    def write(_packet); end

    def read_ber(*)
      @response
    end

    def close; end
  end

  # Serves raw BER bytes (like a real socket) instead of pre-parsed arrays.
  class RawWire
    def initialize(response_bytes)
      @response_bytes = response_bytes
    end

    attr_reader :packets

    def write(packet)
      (@packets ||= []) << packet
      packet.bytesize
    end

    def read_ber(*)
      @response_bytes.read_ber(Net::LDAP::AsnSyntax)
    end

    def close; end
  end

  def self.raw_write_response(code, response_tag, controls = nil)
    result_body = code.to_ber_enumerated + ''.to_ber + ''.to_ber
    result = [0x60 + response_tag].pack('C') + result_body.bytesize.to_ber_length_encoding + result_body
    elements = [1.to_ber, result]
    elements << controls if controls
    elements.to_ber_sequence
  end

  # Builds a real read-entry response control (BER SEQUENCE whose value is
  # an OCTET STRING wrapping the SearchEntryDNAttributeValue).
  def self.raw_read_entry_control(oid, dn:, attributes: {})
    attrs = attributes.map do |name, values|
      values = Array(values).map do |value|
        value.encoding == Encoding::BINARY ? value.to_ber_bin : value.to_ber
      end
      [name.to_s.to_ber, values.to_ber_set].to_ber_sequence
    end
    entry = [dn.to_ber, attrs.to_ber_sequence].to_ber_sequence
    [oid.to_ber, true.to_ber, entry.to_ber_bin].to_ber_sequence
  end

  def self.write_response(code, response_tag, controls = nil, message_id = 1)
    app = Net::BER::BerIdentifiedArray.new([code, '', ''])
    app.ber_identifier = response_tag
    message = [message_id, app]
    message << controls if controls
    message
  end

  # Returns the control in the shape produced by Net::BER parsing: an array
  # [oid, criticality, value] whose value is the SearchEntryDNAttributeValue
  # parsed as [dn, [[attribute, [values]], ...]].
  def self.read_entry_control(oid, dn:, attributes: {})
    attrs = attributes.map do |name, values|
      [name.to_s, Array(values)]
    end
    [oid, true, [dn, attrs]]
  end

  def self.controls_container(*controls)
    Net::BER::BerIdentifiedArray.new(controls)
  end

  def setup
    @filter = Net::LDAP::Filter.eq('version', '7')
  end

  def new_connection(handler = nil, &block)
    wire = FakeWire.new(handler, &block)
    [Net::LDAP::Connection.new(:socket => wire), wire]
  end

  def modify_args(extra = {})
    {
      :dn => DN,
      :operations => [[:replace, 'version', '8']],
    }.merge(extra)
  end

  def request_controls(packet)
    packet.read_ber(Net::LDAP::AsnSyntax)[2] || []
  end

  def control_by_oid(controls, oid)
    controls.find { |control| control[0] == oid }
  end

  #-- Request encoding -----------------------------------------------------

  def test_modify_sends_assertion_pre_read_and_post_read_in_one_write
    response = self.class.write_response(Net::LDAP::ResultCodeSuccess,
                                         Net::LDAP::PDU::ModifyResponse)
    conn, wire = new_connection(response)

    conn.modify(modify_args(
      :assertion => @filter,
      :pre_read => ['version'],
      :post_read => true,
    ))

    assert_equal 1, wire.packets.length, 'only one write request may be sent'
    controls = request_controls(wire.packets.first)
    assert_equal [ASSERTION_OID, PRE_READ_OID, POST_READ_OID], controls.map(&:first)
    assert controls.all? { |control| control[1] == true }, 'semantic controls must be critical'

    request = wire.packets.first.read_ber(Net::LDAP::AsnSyntax)
    assert_equal Net::LDAP::PDU::ModifyRequest, request[1].ber_identifier & 0x1f
  end

  def test_assertion_filter_is_encoded_with_the_existing_filter_object
    response = self.class.write_response(Net::LDAP::ResultCodeSuccess,
                                         Net::LDAP::PDU::ModifyResponse)
    conn, wire = new_connection(response)

    binary = ['000102ff'].pack('H*')
    conn.modify(modify_args(:assertion => Net::LDAP::Filter.bineq('objectGUID', binary)))

    assertion = control_by_oid(request_controls(wire.packets.first), ASSERTION_OID)
    assert_equal 0xa3, assertion[2].ber_identifier # equalityMatch [3]
    assert_equal binary, assertion[2][1]
  end

  def test_pre_read_attribute_selection_is_sequence_of_attribute_names
    response = self.class.write_response(Net::LDAP::ResultCodeSuccess,
                                         Net::LDAP::PDU::ModifyResponse)
    conn, wire = new_connection(response)

    conn.modify(modify_args(:assertion => @filter, :pre_read => [:cn, 'mail']))

    pre_read = control_by_oid(request_controls(wire.packets.first), PRE_READ_OID)
    assert_equal 0x04, pre_read[2].ber_identifier
    selection = StringIO.new(pre_read[2]).read_ber
    assert_equal %w[cn mail], selection
  end

  def test_post_read_true_and_empty_attribute_set_are_sent_as_empty_selection
    response = self.class.write_response(Net::LDAP::ResultCodeSuccess,
                                         Net::LDAP::PDU::ModifyResponse)
    all_conn, all_wire = new_connection(response)
    all_conn.modify(modify_args(:post_read => true))
    empty_conn, empty_wire = new_connection(response)
    empty_conn.modify(modify_args(:post_read => []))

    [all_wire.packets.first, empty_wire.packets.first].each do |packet|
      # controlValue OCTET STRING wrapping an empty SEQUENCE OF names
      assert packet.include?([0x04, 0x02, 0x30, 0x00].pack('C4'))
      value = control_by_oid(request_controls(packet), POST_READ_OID)[2]
      assert_equal [0x30, 0x00].pack('C2'), String.new(value)
      assert_equal [], StringIO.new(value).read_ber
    end
  end

  def test_post_read_attribute_names_are_sent_as_sequence_of_octet_strings
    response = self.class.write_response(Net::LDAP::ResultCodeSuccess,
                                         Net::LDAP::PDU::ModifyResponse)
    conn, wire = new_connection(response)
    conn.modify(modify_args(:post_read => ['cn', 'mail']))

    value = control_by_oid(request_controls(wire.packets.first), POST_READ_OID)[2]
    selection = StringIO.new(value).read_ber
    assert_equal %w[cn mail], selection
  end

  def test_no_controls_container_is_added_when_nothing_is_requested
    response = self.class.write_response(Net::LDAP::ResultCodeSuccess,
                                         Net::LDAP::PDU::ModifyResponse)
    conn, wire = new_connection(response)

    conn.modify(modify_args)

    parsed = wire.packets.first.read_ber(Net::LDAP::AsnSyntax)
    assert_equal 2, parsed.length
    assert_nil parsed[2]
  end

  def test_supported_and_unsupported_control_combinations_per_write_command
    conn, _wire = new_connection do |request|
      tag = request[1].ber_identifier & 0x1f
      response_tag =
        if tag == Net::LDAP::PDU::DeleteRequest
          Net::LDAP::PDU::DeleteResponse
        else
          Net::LDAP::PDU::ModifyRDNResponse
        end
      self.class.write_response(Net::LDAP::ResultCodeSuccess, response_tag, nil, request[0])
    end

    assert_nothing_raised do
      conn.delete(:dn => DN, :assertion => @filter, :pre_read => true, :post_read => true)
      conn.rename(:olddn => DN, :newrdn => 'cn=renamed',
                  :assertion => @filter, :pre_read => true, :post_read => true)
    end

    assert_raise ArgumentError do
      conn.add(:dn => DN, :attributes => { 'cn' => 'x' }, :pre_read => true)
    end
    assert_raise ArgumentError do
      conn.add(:dn => DN, :attributes => { 'cn' => 'x' }, :assertion => 'version=7')
    end
  end

  def test_add_supports_assertion_and_post_read_but_not_pre_read
    response = self.class.write_response(Net::LDAP::ResultCodeSuccess,
                                         Net::LDAP::PDU::AddResponse)
    conn, wire = new_connection(response)

    conn.add(:dn => DN, :attributes => { 'cn' => 'x' },
             :assertion => @filter, :post_read => true)

    controls = request_controls(wire.packets.first)
    assert_equal [ASSERTION_OID, POST_READ_OID], controls.map(&:first)
  end

  def test_invalid_read_entry_arguments_are_rejected
    response = self.class.write_response(Net::LDAP::ResultCodeSuccess,
                                         Net::LDAP::PDU::ModifyResponse)
    conn, _wire = new_connection(response)

    assert_raise ArgumentError do
      conn.modify(modify_args(:pre_read => 7))
    end
    assert_raise ArgumentError do
      conn.modify(modify_args(:post_read => ['cn', 7]))
    end
  end

  def test_duplicate_control_oids_between_semantic_and_custom_controls_are_rejected
    custom = [[PRE_READ_OID, true, [0x04, 0x02, 0x30, 0x00].pack('C4')]]
    response = self.class.write_response(Net::LDAP::ResultCodeSuccess,
                                         Net::LDAP::PDU::ModifyResponse)
    conn, _wire = new_connection(response)

    assert_raise ArgumentError do
      conn.modify(modify_args(:pre_read => true, :controls => custom))
    end
  end

  def test_controls_and_control_codes_cannot_be_supplied_together
    conn, _wire = new_connection

    assert_raise ArgumentError do
      conn.delete(:dn => DN,
                  :controls => [],
                  :control_codes => [[Net::LDAP::LDAPControls::DELETE_TREE, true]])
    end
  end

  def test_legacy_tuple_controls_and_sequence_of_controls_are_normalized
    response = self.class.write_response(Net::LDAP::ResultCodeSuccess,
                                         Net::LDAP::PDU::ModifyResponse)
    tuple_conn, tuple_wire = new_connection(response)
    tuple_controls = [['1.2.840.113556.1.4.801', true, [0x04, 0x01, 0x04].pack('C3')]]
    tuple_conn.modify(modify_args(:controls => tuple_controls))

    sequence = tuple_controls.to_ber_control
    sequence_conn, sequence_wire = new_connection(response)
    sequence_conn.modify(modify_args(:controls => sequence))

    [tuple_wire, sequence_wire].each do |wire|
      controls = request_controls(wire.packets.first)
      assert_equal ['1.2.840.113556.1.4.801'], controls.map(&:first)
      assert_equal [true], controls.map { |control| control[1] }
    end
  end

  def test_control_codes_are_wrapped_as_a_controls_container_for_delete
    response = self.class.write_response(Net::LDAP::ResultCodeSuccess,
                                         Net::LDAP::PDU::DeleteResponse)
    conn, wire = new_connection(response)

    conn.delete(:dn => DN,
                :control_codes => [[Net::LDAP::LDAPControls::DELETE_TREE, true]])

    parsed = FakeWire.send(:new, nil).send(:parse_packet, wire.packets.first)
    assert_equal Net::LDAP::PDU::DeleteRequest, parsed[1].ber_identifier & 0x1f
    assert_equal [Net::LDAP::LDAPControls::DELETE_TREE], parsed[2].map(&:first)
  end

  #-- Response controls and result classification --------------------------

  def test_pre_and_post_entries_come_from_the_corresponding_response_controls
    pre = self.class.read_entry_control(PRE_READ_OID, :dn => DN,
                                       :attributes => { 'version' => ['7'] })
    post = self.class.read_entry_control(POST_READ_OID, :dn => DN,
                                        :attributes => { 'version' => ['8'] })
    response = self.class.write_response(
      Net::LDAP::ResultCodeSuccess,
      Net::LDAP::PDU::ModifyResponse,
      self.class.controls_container(pre, post)
    )
    conn, _wire = new_connection(response)

    pdu = conn.modify(modify_args(:assertion => @filter,
                                 :pre_read => ['version'],
                                 :post_read => ['version']))

    assert_equal :provided, pdu.pre_read_status
    assert_equal :provided, pdu.post_read_status
    assert_equal ['7'], pdu.pre_read_entry[:version]
    assert_equal ['8'], pdu.post_read_entry[:version]
    assert_equal DN, pdu.pre_read_entry.dn
    assert_equal DN, pdu.post_read_entry.dn
    assert_equal [PRE_READ_OID, POST_READ_OID], pdu.ldap_controls.map(&:oid)
  end

  def test_binary_and_duplicate_attribute_values_are_preserved
    binary = ['0001fe'].pack('H*')
    post = self.class.read_entry_control(
      POST_READ_OID, :dn => DN,
      :attributes => {
        'mail' => ['one@example.com', 'two@example.com'],
        'bin' => [binary],
      }
    )
    response = self.class.write_response(
      Net::LDAP::ResultCodeSuccess,
      Net::LDAP::PDU::ModifyResponse,
      self.class.controls_container(post)
    )
    conn, _wire = new_connection(response)

    pdu = conn.modify(modify_args(:post_read => true))

    assert_equal ['one@example.com', 'two@example.com'], pdu.post_read_entry[:mail]
    assert_equal [binary], pdu.post_read_entry[:bin]
    assert_equal Encoding::BINARY, pdu.post_read_entry[:bin].first.encoding
  end

  def test_read_entries_parse_from_real_ber_response_bytes
    binary = ['0001fe'].pack('H*')
    pre = self.class.raw_read_entry_control(
      PRE_READ_OID, :dn => DN, :attributes => { 'version' => ['7'] }
    )
    post = self.class.raw_read_entry_control(
      POST_READ_OID, :dn => DN,
      :attributes => {
        'version' => ['8'],
        'mail' => ['one@example.com', 'two@example.com'],
        'bin' => [binary],
      }
    )
    controls = [pre, post].to_ber_contextspecific(0)
    packet = self.class.raw_write_response(Net::LDAP::ResultCodeSuccess,
                                          Net::LDAP::PDU::ModifyResponse,
                                          controls)
    conn = Net::LDAP::Connection.new(:socket => RawWire.new(packet))

    pdu = conn.modify(modify_args(:assertion => @filter,
                                 :pre_read => true,
                                 :post_read => true))

    assert_equal ['7'], pdu.pre_read_entry[:version]
    assert_equal ['one@example.com', 'two@example.com'], pdu.post_read_entry[:mail]
    assert_equal [binary], pdu.post_read_entry[:bin]
    assert_equal Encoding::BINARY, pdu.post_read_entry[:bin].first.encoding
    assert_equal [PRE_READ_OID, POST_READ_OID], pdu.ldap_controls.map(&:oid)
  end

  def test_empty_attribute_set_returns_entry_without_attributes
    post = self.class.read_entry_control(POST_READ_OID, :dn => DN, :attributes => {})
    response = self.class.write_response(
      Net::LDAP::ResultCodeSuccess,
      Net::LDAP::PDU::ModifyResponse,
      self.class.controls_container(post)
    )
    conn, _wire = new_connection(response)

    pdu = conn.modify(modify_args(:post_read => []))

    assert_equal :provided, pdu.post_read_status
    assert_equal [:dn], pdu.post_read_entry.attribute_names
    assert_equal [], pdu.post_read_entry[:version]
    assert_equal :not_requested, pdu.pre_read_status
    assert_nil pdu.pre_read_entry
  end

  def test_not_requested_not_provided_and_provided_are_distinguishable
    # pre-read requested but omitted by the server; post-read provided.
    post = self.class.read_entry_control(POST_READ_OID, :dn => DN,
                                        :attributes => { 'version' => ['8'] })
    response = self.class.write_response(
      Net::LDAP::ResultCodeSuccess,
      Net::LDAP::PDU::ModifyResponse,
      self.class.controls_container(post)
    )
    conn, _wire = new_connection(response)

    pdu = conn.modify(modify_args(:pre_read => true, :post_read => true))

    assert_equal :not_provided, pdu.pre_read_status
    assert_nil pdu.pre_read_entry
    assert_equal :provided, pdu.post_read_status
    assert_equal ['8'], pdu.post_read_entry[:version]
  end

  def test_assertion_failed_is_distinguishable_from_other_errors
    response = self.class.write_response(
      Net::LDAP::ResultCodeAssertionFailed,
      Net::LDAP::PDU::ModifyResponse
    )
    conn, _wire = new_connection(response)

    pdu = conn.modify(modify_args(:assertion => @filter, :pre_read => true))

    assert pdu.assertion_failed?
    assert !pdu.unavailable_critical_extension?
    assert_equal Net::LDAP::ResultCodeAssertionFailed, pdu.result_code
    assert_equal :not_provided, pdu.pre_read_status
  end

  def test_unknown_critical_control_is_distinguishable
    response = self.class.write_response(
      Net::LDAP::ResultCodeUnavailableCriticalExtension,
      Net::LDAP::PDU::ModifyResponse
    )
    conn, _wire = new_connection(response)

    pdu = conn.modify(modify_args(:assertion => @filter))

    assert pdu.unavailable_critical_extension?
    assert !pdu.assertion_failed?
    assert_equal Net::LDAP::ResultCodeUnavailableCriticalExtension, pdu.result_code
  end

  def test_ordinary_write_errors_remain_distinguishable
    response = self.class.write_response(
      Net::LDAP::ResultCodeUnwillingToPerform,
      Net::LDAP::PDU::ModifyResponse
    )
    conn, _wire = new_connection(response)

    pdu = conn.modify(modify_args(:assertion => @filter))

    assert !pdu.assertion_failed?
    assert !pdu.unavailable_critical_extension?
    assert_equal Net::LDAP::ResultCodeUnwillingToPerform, pdu.result_code
  end

  def test_get_operation_result_exposes_entries_statuses_and_error_kind
    pre = self.class.read_entry_control(PRE_READ_OID, :dn => DN,
                                       :attributes => { 'version' => ['7'] })
    post = self.class.read_entry_control(POST_READ_OID, :dn => DN,
                                        :attributes => { 'version' => ['8'] })
    response = self.class.write_response(
      Net::LDAP::ResultCodeSuccess,
      Net::LDAP::PDU::ModifyResponse,
      self.class.controls_container(pre, post)
    )
    ldap = Net::LDAP.new
    ldap.connection = Net::LDAP::Connection.new(:socket => StaticWire.new(response))

    assert ldap.modify(modify_args(:assertion => @filter,
                                  :pre_read => true,
                                  :post_read => true))
    result = ldap.get_operation_result

    assert_equal 0, result.code
    assert_equal :provided, result.pre_read_status
    assert_equal :provided, result.post_read_status
    assert_equal ['7'], result.pre_read_entry[:version]
    assert_equal ['8'], result.post_read_entry[:version]
    assert_equal false, result.assertion_failed
    assert_equal false, result.unavailable_critical_extension
  end

  #-- Atomic conditional update --------------------------------------------

  # A minimal in-memory entry evaluated entirely from the single write
  # packet. Returns a real-BER ModifyResponse parsed into the same shape the
  # socket layer produces.
  def conditional_modify_server(state)
    lambda do |request|
      controls = request[2] || []
      assertion = controls.find { |control| control[0] == ASSERTION_OID }
      pre_requested = controls.any? { |control| control[0] == PRE_READ_OID }
      post_requested = controls.any? { |control| control[0] == POST_READ_OID }
      attribute_value = assertion[2][1] # (version=...) equality filter

      response_controls = []
      unless state[:version] == attribute_value
        return self.class.write_response(
          Net::LDAP::ResultCodeAssertionFailed,
          Net::LDAP::PDU::ModifyResponse, nil, request[0]
        )
      end

      response_controls << self.class.read_entry_control(
        PRE_READ_OID, :dn => DN, :attributes => { 'version' => [state[:version]] }
      ) if pre_requested
      response_controls << self.class.read_entry_control(
        POST_READ_OID, :dn => DN, :attributes => { 'version' => [state[:version].succ] }
      ) if post_requested
      state[:version] = state[:version].succ

      self.class.write_response(
        Net::LDAP::ResultCodeSuccess,
        Net::LDAP::PDU::ModifyResponse,
        response_controls.empty? ? nil : self.class.controls_container(*response_controls),
        request[0]
      )
    end
  end

  def test_two_callers_with_the_same_old_version_one_succeeds_one_fails
    state = { :version => '7' }
    conn, wire = new_connection(conditional_modify_server(state))

    args = modify_args(
      :assertion => @filter,
      :pre_read => ['version'],
      :post_read => ['version'],
    )

    first = conn.modify(args)
    second = conn.modify(args)

    assert_equal 2, wire.packets.length
    assert_equal 0, first.result_code
    assert_equal :provided, first.pre_read_status
    assert_equal :provided, first.post_read_status
    assert_equal ['7'], first.pre_read_entry[:version]
    assert_equal ['8'], first.post_read_entry[:version]

    assert_equal Net::LDAP::ResultCodeAssertionFailed, second.result_code
    assert second.assertion_failed?
    assert !second.unavailable_critical_extension?
    assert_equal '8', state[:version]
  end

  def test_each_conditional_modify_is_exactly_one_write_request
    state = { :version => '7' }
    conn, wire = new_connection(conditional_modify_server(state))

    conn.modify(modify_args(:assertion => @filter, :pre_read => true, :post_read => true))
    conn.modify(modify_args(:assertion => @filter, :pre_read => true, :post_read => true))

    assert_equal 2, wire.packets.length
    wire.packets.each do |packet|
      parsed = packet.read_ber(Net::LDAP::AsnSyntax)
      assert_equal Net::LDAP::PDU::ModifyRequest, parsed[1].ber_identifier & 0x1f
      oids = parsed[2].map(&:first)
      assert_equal [ASSERTION_OID, PRE_READ_OID, POST_READ_OID], oids
    end
  end
end
