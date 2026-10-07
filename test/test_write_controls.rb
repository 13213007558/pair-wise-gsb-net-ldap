require_relative 'test_helper'

# Tests for RFC 4528 (assertion control) and RFC 4527 (pre-read /
# post-read controls) attached to single write operations.
class TestWriteControls < Test::Unit::TestCase
  DN = "cn=app,dc=example,dc=com"

  # Builds a binary string from a byte-separated hex dump.
  def self.ber(hex)
    [hex.gsub(" ", "")].pack("H*")
  end

  # BER protocol samples, verified byte-for-byte against the wire format.
  ASSERTION_VERSION_7 = ber(
    "30 21 04 0c 31 2e 33 2e 36 2e 31 2e 31 2e 31 32 01 01 ff"     " 04 0e a3 0c 04 07 76 65 72 73 69 6f 6e 04 01 37"
  )
  PRE_READ_VERSION = ber(
    "30 20 04 0e 31 2e 33 2e 36 2e 31 2e 31 2e 31 33 2e 31 01 01 ff"     " 04 0b 30 09 04 07 76 65 72 73 69 6f 6e"
  )
  POST_READ_VERSION = ber(
    "30 20 04 0e 31 2e 33 2e 36 2e 31 2e 31 2e 31 33 2e 32 01 01 ff"     " 04 0b 30 09 04 07 76 65 72 73 69 6f 6e"
  )
  PRE_READ_VERSION_AND_BINARY_CERT = ber(
    "30 38 04 0e 31 2e 33 2e 36 2e 31 2e 31 2e 31 33 2e 31 01 01 ff"     " 04 23 30 21 04 07 76 65 72 73 69 6f 6e"     " 04 16 75 73 65 72 43 65 72 74 69 66 69 63 61 74 65 3b 62 69 6e 61 72 79"
  )
  POST_READ_VERSION_NOT_CRITICAL = ber(
    "30 20 04 0e 31 2e 33 2e 36 2e 31 2e 31 2e 31 33 2e 32 01 01 00"     " 04 0b 30 09 04 07 76 65 72 73 69 6f 6e"
  )
  DELETE_TREE_CONTROL = ber(
    "30 1b 04 16 31 2e 32 2e 38 34 30 2e 31 31 33 35 35 36 2e 31 2e 34 2e 38 30 35"     " 01 01 ff"
  )

  # A small socket double: records everything written, serves canned
  # BER responses on read.
  class FakeLdapSocket
    attr_reader :written

    def initialize(response)
      @response = StringIO.new(response)
      @written = []
    end

    def write(data)
      @written << data
      data.bytesize
    end

    def read_ber(syntax = nil, &block)
      @response.read_ber(syntax, &block)
    end

    def close; end
  end

  def ldap_for(response)
    socket = FakeLdapSocket.new(response)
    connection = Net::LDAP::Connection.new(:socket => socket)
    ldap = Net::LDAP.new
    ldap.connection = connection
    [ldap, socket]
  end

  # BER for an LDAPResult message with optional response controls.
  def build_response(message_id, app_tag, result_code, controls = [])
    response = [result_code.to_ber_enumerated, "".to_ber, "".to_ber].to_ber_appsequence(app_tag)
    packet = [message_id.to_ber, response]
    packet << controls.to_ber_contextspecific(0) unless controls.empty?
    packet.to_ber_sequence
  end

  # BER for a pre-read / post-read response control carrying a
  # SearchEntry value.
  def entry_control(oid, dn, attributes)
    value = [
      dn.to_ber,
      attributes.map { |name, values|
        [name.to_ber, values.map { |v| v.to_ber_bin }.to_ber_set].to_ber_sequence
      }.to_ber_sequence,
    ].to_ber_sequence
    [oid.to_ber, true.to_ber, value.to_ber_bin].to_ber_sequence
  end

  def message_controls(packet)
    _msgid, _request, controls = packet.read_ber(Net::LDAP::AsnSyntax)
    controls
  end

  # -- control encoding -------------------------------------------------

  def test_assertion_control_encoding
    built = Net::LDAP::Controls.build(:modify, :assertion => Net::LDAP::Filter.eq(:version, 7))
    assert_equal [ASSERTION_VERSION_7], built.controls
    refute built.pre_read_requested?
    refute built.post_read_requested?
  end

  def test_assertion_accepts_a_filter_string
    built = Net::LDAP::Controls.build(:modify, :assertion => "(version=7)")
    assert_equal [ASSERTION_VERSION_7], built.controls
  end

  def test_assertion_rejects_non_filter_values
    assert_raise(ArgumentError) do
      Net::LDAP::Controls.build(:modify, :assertion => 42)
    end
  end

  def test_pre_read_control_encoding
    built = Net::LDAP::Controls.build(:modify, :pre_read => %w(version))
    assert built.pre_read_requested?
    assert_equal [PRE_READ_VERSION], built.controls
  end

  def test_pre_read_control_encoding_with_binary_attribute
    built = Net::LDAP::Controls.build(:modify, :pre_read => ["version", "userCertificate;binary"])
    assert_equal [PRE_READ_VERSION_AND_BINARY_CERT], built.controls
  end

  def test_post_read_control_encoding
    built = Net::LDAP::Controls.build(:modify, :post_read => %w(version))
    assert built.post_read_requested?
    assert_equal [POST_READ_VERSION], built.controls
  end

  def test_read_control_criticality_can_be_relaxed
    built = Net::LDAP::Controls.build(:modify, :post_read => { :attributes => %w(version), :criticality => false })
    assert built.post_read_requested?
    assert_equal [POST_READ_VERSION_NOT_CRITICAL], built.controls
  end

  def test_attribute_description_validation
    ["cn", "2.5.4.3", "userCertificate;binary"].each do |description|
      built = Net::LDAP::Controls.build(:modify, :pre_read => [description])
      assert built.pre_read_requested?
    end
    ["", "not an attribute", "cn;", ";binary", 7, nil].each do |description|
      assert_raise(ArgumentError) do
        Net::LDAP::Controls.build(:modify, :pre_read => [description])
      end
    end
  end

  def test_read_controls_restricted_per_operation
    assert_raise(ArgumentError) { Net::LDAP::Controls.build(:add, :pre_read => %w(cn)) }
    assert_raise(ArgumentError) { Net::LDAP::Controls.build(:delete, :post_read => %w(cn)) }
    assert Net::LDAP::Controls.build(:add, :post_read => %w(cn)).post_read_requested?
    assert Net::LDAP::Controls.build(:delete, :pre_read => %w(cn)).pre_read_requested?
    both = Net::LDAP::Controls.build(:rename, :pre_read => %w(cn), :post_read => %w(cn))
    assert both.pre_read_requested?
    assert both.post_read_requested?
  end

  def test_assertion_allowed_on_all_write_operations
    [:add, :modify, :delete, :rename].each do |operation|
      built = Net::LDAP::Controls.build(operation, :assertion => Net::LDAP::Filter.eq(:version, 7))
      assert_equal [ASSERTION_VERSION_7], built.controls
    end
    assert_raise(ArgumentError) do
      Net::LDAP::Controls.build(:search, :assertion => Net::LDAP::Filter.eq(:version, 7))
    end
  end

  # -- single-request wire proof ----------------------------------------

  def test_modify_with_controls_sends_a_single_write_request
    response = build_response(1, Net::LDAP::PDU::ModifyResponse, Net::LDAP::ResultCodeSuccess)
    ldap, socket = ldap_for(response)

    assert ldap.modify(:dn => DN,
                       :operations => [[:replace, :version, 8]],
                       :assertion => Net::LDAP::Filter.eq(:version, 7),
                       :pre_read => %w(version),
                       :post_read => %w(version))

    # Exactly one LDAPMessage went over the wire: a single ModifyRequest
    # carrying all three controls. No search is issued to emulate the
    # condition.
    assert_equal 1, socket.written.size
    message_id, request, controls = socket.written[0].read_ber(Net::LDAP::AsnSyntax)
    assert_equal 1, message_id
    assert_equal 0x66, request.ber_identifier # [APPLICATION 6] ModifyRequest
    assert_equal 0xa0, controls.ber_identifier # [0] Controls

    expected_controls = self.class.ber(
      "a0 67"
    ) + ASSERTION_VERSION_7 + PRE_READ_VERSION + POST_READ_VERSION
    assert socket.written[0].end_with?(expected_controls)

    oids = controls.map { |control| control[0] }
    assert_equal [Net::LDAP::Controls::ASSERTION,
                  Net::LDAP::Controls::PRE_READ,
                  Net::LDAP::Controls::POST_READ], oids
    assert controls.all? { |control| control[1] == true }
  end

  def test_add_with_assertion_and_post_read
    post = entry_control(Net::LDAP::Controls::POST_READ, DN, [["version", ["7"]]])
    response = build_response(1, Net::LDAP::PDU::AddResponse, Net::LDAP::ResultCodeSuccess, [post])
    ldap, socket = ldap_for(response)

    assert ldap.add(:dn => DN,
                    :attributes => { :cn => "app", :version => 7 },
                    :assertion => "(objectClass=applicationProcess)",
                    :post_read => %w(version))

    assert_equal 1, socket.written.size
    _msgid, request, controls = socket.written[0].read_ber(Net::LDAP::AsnSyntax)
    assert_equal 0x68, request.ber_identifier # [APPLICATION 8] AddRequest
    assert_equal [Net::LDAP::Controls::ASSERTION, Net::LDAP::Controls::POST_READ],
                 controls.map { |control| control[0] }
    assert_equal ["7"], ldap.get_operation_result.post_read_entry.version
  end

  def test_delete_merges_control_codes_and_write_controls
    response = build_response(1, Net::LDAP::PDU::DeleteResponse, Net::LDAP::ResultCodeSuccess)
    ldap, socket = ldap_for(response)

    assert ldap.delete(:dn => DN,
                       :control_codes => [[Net::LDAP::LDAPControls::DELETE_TREE, true]],
                       :assertion => Net::LDAP::Filter.eq(:version, 7),
                       :pre_read => %w(version))

    # One DeleteRequest, one controls element, three controls in order.
    assert_equal 1, socket.written.size
    assert socket.written[0].include?("\x4a\x18" + DN) # [APPLICATION 10] DN
    expected_controls = self.class.ber("a0 62") + DELETE_TREE_CONTROL + ASSERTION_VERSION_7 + PRE_READ_VERSION
    assert socket.written[0].end_with?(expected_controls)
  end

  def test_rename_supports_all_three_controls
    response = build_response(1, Net::LDAP::PDU::ModifyRDNResponse, Net::LDAP::ResultCodeSuccess)
    ldap, socket = ldap_for(response)

    assert ldap.rename(:olddn => DN,
                       :newrdn => "cn=app2",
                       :assertion => Net::LDAP::Filter.eq(:version, 7),
                       :pre_read => %w(cn),
                       :post_read => %w(cn))

    assert_equal 1, socket.written.size
    _msgid, request, controls = socket.written[0].read_ber(Net::LDAP::AsnSyntax)
    assert_equal 0x6c, request.ber_identifier # [APPLICATION 12] ModifyRDNRequest
    assert_equal [Net::LDAP::Controls::ASSERTION,
                  Net::LDAP::Controls::PRE_READ,
                  Net::LDAP::Controls::POST_READ],
                 controls.map { |control| control[0] }
  end

  # -- response entries and result states --------------------------------

  def test_pre_and_post_read_entries_come_from_response_controls
    pre = entry_control(Net::LDAP::Controls::PRE_READ, DN, [["version", ["7"]], ["cn", ["app"]]])
    post = entry_control(Net::LDAP::Controls::POST_READ, DN, [["version", ["8"]]])
    response = build_response(1, Net::LDAP::PDU::ModifyResponse, Net::LDAP::ResultCodeSuccess, [pre, post])
    ldap, = ldap_for(response)

    assert ldap.modify(:dn => DN,
                       :operations => [[:replace, :version, 8]],
                       :pre_read => %w(version cn),
                       :post_read => %w(version))

    result = ldap.get_operation_result
    assert_kind_of Net::LDAP::Entry, result.pre_read_entry
    assert_equal DN, result.pre_read_entry.dn
    assert_equal ["7"], result.pre_read_entry.version
    assert_equal ["app"], result.pre_read_entry.cn
    assert_kind_of Net::LDAP::Entry, result.post_read_entry
    assert_equal ["8"], result.post_read_entry.version
  end

  def test_read_entries_not_requested
    response = build_response(1, Net::LDAP::PDU::ModifyResponse, Net::LDAP::ResultCodeSuccess)
    ldap, = ldap_for(response)

    assert ldap.modify(:dn => DN, :operations => [[:replace, :version, 8]])

    result = ldap.get_operation_result
    assert_nil result.pre_read_entry
    assert_nil result.post_read_entry
  end

  def test_read_entry_requested_but_not_provided_by_server
    response = build_response(1, Net::LDAP::PDU::ModifyResponse, Net::LDAP::ResultCodeSuccess)
    ldap, = ldap_for(response)

    assert ldap.modify(:dn => DN,
                       :operations => [[:replace, :version, 8]],
                       :pre_read => %w(version))

    result = ldap.get_operation_result
    assert_same Net::LDAP::Controls::ENTRY_NOT_PROVIDED, result.pre_read_entry
    assert_nil result.post_read_entry
  end

  def test_read_entry_with_empty_attribute_set
    pre = entry_control(Net::LDAP::Controls::PRE_READ, DN, [])
    response = build_response(1, Net::LDAP::PDU::ModifyResponse, Net::LDAP::ResultCodeSuccess, [pre])
    ldap, = ldap_for(response)

    assert ldap.modify(:dn => DN,
                       :operations => [[:replace, :version, 8]],
                       :pre_read => [])

    result = ldap.get_operation_result
    assert_kind_of Net::LDAP::Entry, result.pre_read_entry
    assert_equal DN, result.pre_read_entry.dn
    assert_equal [:dn], result.pre_read_entry.attribute_names
  end

  def test_binary_attribute_values_are_preserved
    certificate = "\x30\x82\x01\x00\xff\xfe\x00\x7f".b
    pre = entry_control(Net::LDAP::Controls::PRE_READ, DN, [["userCertificate;binary", [certificate]]])
    response = build_response(1, Net::LDAP::PDU::ModifyResponse, Net::LDAP::ResultCodeSuccess, [pre])
    ldap, = ldap_for(response)

    assert ldap.modify(:dn => DN,
                       :operations => [[:replace, :version, 8]],
                       :pre_read => ["userCertificate;binary"])

    entry = ldap.get_operation_result.pre_read_entry
    assert_equal [certificate], entry["userCertificate;binary"].map(&:b)
  end

  def test_duplicate_attribute_values_are_preserved
    pre = entry_control(Net::LDAP::Controls::PRE_READ, DN, [["cn", ["app", "app"]]])
    response = build_response(1, Net::LDAP::PDU::ModifyResponse, Net::LDAP::ResultCodeSuccess, [pre])
    ldap, = ldap_for(response)

    assert ldap.modify(:dn => DN,
                       :operations => [[:replace, :version, 8]],
                       :pre_read => %w(cn))

    assert_equal ["app", "app"], ldap.get_operation_result.pre_read_entry.cn
  end

  def test_malformed_read_entry_control_value_is_rejected
    assert_raise(Net::LDAP::BERInvalidError) do
      Net::LDAP::Controls.parse_entry("\x30\x03\x02\x01\x05".b) # SEQUENCE { INTEGER 5 }
    end
    assert_raise(Net::LDAP::BERInvalidError) do
      Net::LDAP::Controls.parse_entry("\x30\x05\x04\x02".b) # truncated
    end
  end

  # -- distinguishable failure modes -------------------------------------

  def test_unavailable_critical_extension_is_distinguishable
    response = build_response(1, Net::LDAP::PDU::ModifyResponse,
                              Net::LDAP::ResultCodeUnavailableCriticalExtension)
    ldap, = ldap_for(response)

    refute ldap.modify(:dn => DN,
                       :operations => [[:replace, :version, 8]],
                       :assertion => Net::LDAP::Filter.eq(:version, 7))

    result = ldap.get_operation_result
    assert_equal Net::LDAP::ResultCodeUnavailableCriticalExtension, result.code
    assert result.unavailable_critical_extension?
    refute result.assertion_failed?
    refute result.success?
  end

  def test_ordinary_write_error_is_distinguishable
    response = build_response(1, Net::LDAP::PDU::ModifyResponse,
                              Net::LDAP::ResultCodeObjectClassViolation)
    ldap, = ldap_for(response)

    refute ldap.modify(:dn => DN, :operations => [[:replace, :version, 8]])

    result = ldap.get_operation_result
    assert_equal Net::LDAP::ResultCodeObjectClassViolation, result.code
    refute result.assertion_failed?
    refute result.unavailable_critical_extension?
    refute result.success?
  end

  # -- the race: two callers, one old version ----------------------------

  def test_two_callers_same_old_version_one_wins_one_gets_assertion_failed
    pre = entry_control(Net::LDAP::Controls::PRE_READ, DN, [["version", ["7"]]])
    post = entry_control(Net::LDAP::Controls::POST_READ, DN, [["version", ["8"]]])
    winner_response = build_response(1, Net::LDAP::PDU::ModifyResponse,
                                     Net::LDAP::ResultCodeSuccess, [pre, post])
    winner, winner_socket = ldap_for(winner_response)

    loser_response = build_response(1, Net::LDAP::PDU::ModifyResponse,
                                    Net::LDAP::ResultCodeAssertionFailed)
    loser, loser_socket = ldap_for(loser_response)

    operation = {
      :dn => DN,
      :operations => [[:replace, :version, 8]],
      :assertion => Net::LDAP::Filter.eq(:version, 7),
      :pre_read => %w(version),
      :post_read => %w(version),
    }

    assert winner.modify(operation), "first caller wins the race"
    refute loser.modify(operation), "second caller loses with assertionFailed"

    # Each caller issued exactly one write request; neither needed a
    # search to emulate the condition.
    assert_equal 1, winner_socket.written.size
    assert_equal 1, loser_socket.written.size

    result = winner.get_operation_result
    assert result.success?
    refute result.assertion_failed?
    assert_equal ["7"], result.pre_read_entry.version
    assert_equal ["8"], result.post_read_entry.version

    result = loser.get_operation_result
    assert_equal Net::LDAP::ResultCodeAssertionFailed, result.code
    assert_equal "Assertion Failed", result.message
    assert result.assertion_failed?
    refute result.success?
    refute result.unavailable_critical_extension?
    assert_same Net::LDAP::Controls::ENTRY_NOT_PROVIDED, result.pre_read_entry
    assert_same Net::LDAP::Controls::ENTRY_NOT_PROVIDED, result.post_read_entry
  end
end
