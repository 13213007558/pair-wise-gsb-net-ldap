# -*- ruby encoding: utf-8 -*-
##
# LDAP controls for conditional and read-back write operations.
#
# This module implements the client side of:
#
# * RFC 4528 (LDAP Assertion Control), which makes a single write
#   operation conditional on a search filter that the server evaluates
#   against the target entry as part of the write itself, and
# * RFC 4527 (LDAP Read Entry Controls), which asks the server to return
#   the target entry exactly as it was immediately before (pre-read)
#   and/or immediately after (post-read) the write.
#
# All three controls travel on the same request as the write operation,
# so the condition check and the read-back are atomic with the write.
# There is no need (and no way here) to emulate the condition with a
# separate search followed by a modify, which would be racy.
#
# Example:
#
#   ldap.modify(
#     :dn => dn,
#     :operations => [[:replace, :version, 8]],
#     :assertion => Net::LDAP::Filter.eq(:version, 7),
#     :pre_read  => %w(version cn),
#     :post_read => %w(version),
#   )
#   result = ldap.get_operation_result
#   result.assertion_failed?        # => false
#   result.pre_read_entry.version   # => ["7"]
#   result.post_read_entry.version  # => ["8"]
#
module Net::LDAP::Controls
  # RFC 4528 - LDAP Assertion Control
  ASSERTION = "1.3.6.1.1.12"
  # RFC 4527 - LDAP Pre-Read Control
  PRE_READ = "1.3.6.1.1.13.1"
  # RFC 4527 - LDAP Post-Read Control
  POST_READ = "1.3.6.1.1.13.2"

  ##
  # Sentinel returned by Net::LDAP#get_operation_result for
  # #pre_read_entry / #post_read_entry when the corresponding control was
  # requested but the server did not include it in the response. This is
  # distinct from +nil+ (the control was never requested) and from a
  # Net::LDAP::Entry with an empty attribute set (the server returned the
  # entry without any attributes).
  ENTRY_NOT_PROVIDED = Object.new

  class << ENTRY_NOT_PROVIDED
    def inspect
      "Net::LDAP::Controls::ENTRY_NOT_PROVIDED"
    end
    alias_method :to_s, :inspect
  end

  # Which read-entry controls each write operation may carry, per RFC 4527
  # (the assertion control of RFC 4528 is allowed on all of them).
  READ_CONTROLS_BY_OPERATION = {
    :add    => { :pre_read => false, :post_read => true  },
    :modify => { :pre_read => true,  :post_read => true  },
    :delete => { :pre_read => true,  :post_read => false },
    :rename => { :pre_read => true,  :post_read => true  },
  }.freeze

  # AttributeDescription (RFC 4512 section 2.5): an attribute type (a
  # short name or a numeric OID) followed by zero or more options, such
  # as ";binary" for binary-valued attributes.
  ATTRIBUTE_DESCRIPTION = /\A(?:[A-Za-z][A-Za-z0-9-]*|(?:\d+\.)+\d+)(?:;[A-Za-z0-9-]+)*\z/

  ##
  # The validated, BER-encoded controls for one write operation, plus
  # which read-entry controls were requested (so the response can be
  # interpreted later).
  class WriteControls
    attr_reader :controls
    attr_reader :operation

    def initialize(operation)
      @operation = operation
      @controls = []
      @requested = { :pre_read => false, :post_read => false }
    end

    def pre_read_requested?
      @requested[:pre_read]
    end

    def post_read_requested?
      @requested[:post_read]
    end

    def empty?
      @controls.empty?
    end

    def add_assertion(value)
      @controls << Net::LDAP::Controls.encode_control(ASSERTION, true, value)
    end

    def add_pre_read(value, criticality)
      @requested[:pre_read] = true
      @controls << Net::LDAP::Controls.encode_control(PRE_READ, criticality, value)
    end

    def add_post_read(value, criticality)
      @requested[:post_read] = true
      @controls << Net::LDAP::Controls.encode_control(POST_READ, criticality, value)
    end
  end

  ##
  # Validates the :assertion, :pre_read and :post_read options of a write
  # operation and encodes them as BER control sequences (the same form
  # accepted by the :controls option of the connection methods).
  #
  # +operation+ is one of :add, :modify, :delete or :rename.
  #
  # Raises ArgumentError when a control is not allowed on the given
  # operation, when the assertion is not a Net::LDAP::Filter (or a String
  # that parses into one), or when an attribute description is invalid.
  def self.build(operation, args)
    allowed = READ_CONTROLS_BY_OPERATION[operation]
    raise ArgumentError, "unknown write operation: #{operation.inspect}" unless allowed

    built = WriteControls.new(operation)

    if (assertion = args[:assertion])
      built.add_assertion(assertion_value(assertion))
    end

    if (pre_read = args[:pre_read])
      ensure_allowed!(operation, :pre_read, allowed)
      value, criticality = attribute_selection(pre_read)
      built.add_pre_read(value, criticality)
    end

    if (post_read = args[:post_read])
      ensure_allowed!(operation, :post_read, allowed)
      value, criticality = attribute_selection(post_read)
      built.add_post_read(value, criticality)
    end

    built
  end

  ##
  # Encodes a single control as a BER sequence. +value+ must already be
  # BER-encoded; it is wrapped in the controlValue OCTET STRING without
  # re-encoding, so binary content is preserved byte-for-byte.
  def self.encode_control(oid, criticality, value)
    [oid.to_ber, criticality.to_ber, value.to_ber_bin].to_ber_sequence
  end

  ##
  # Parses the controlValue of a pre-read or post-read response control
  # into a Net::LDAP::Entry. The value is a BER-encoded SearchEntry
  # (RFC 4527 section 2). Attribute values are kept as-is: binary values
  # are not re-encoded and duplicate values are preserved.
  def self.parse_entry(value)
    dn, attributes = value.to_s.b.read_ber(Net::LDAP::AsnSyntax)

    unless dn.is_a?(String) && attributes.is_a?(Array)
      raise Net::LDAP::BERInvalidError, "malformed read-entry control value"
    end

    entry = Net::LDAP::Entry.new(dn)
    attributes.each do |attribute|
      name, values = attribute
      unless name.is_a?(String) && values.is_a?(Array)
        raise Net::LDAP::BERInvalidError, "malformed attribute in read-entry control value"
      end
      entry[name] = values
    end
    entry
  rescue Net::BER::BerError => e
    raise Net::LDAP::BERInvalidError, "invalid read-entry control value: #{e.message}"
  end

  ##
  # The AssertionControlValue is a BER-encoded SearchFilter (RFC 4528
  # section 3), built from the existing Net::LDAP::Filter object.
  def self.assertion_value(assertion)
    filter =
      case assertion
      when Net::LDAP::Filter
        assertion
      when String
        Net::LDAP::Filter.construct(assertion)
      else
        raise ArgumentError,
              "assertion must be a Net::LDAP::Filter or a filter String, got #{assertion.class}"
      end
    filter.to_ber
  end
  private_class_method :assertion_value

  ##
  # The controlValue of the pre-read and post-read request controls is an
  # AttributeSelection: a SEQUENCE OF AttributeDescription (RFC 4527
  # section 2). Accepts an array of attribute descriptions, or a Hash of
  # the form { :attributes => [...], :criticality => false }.
  #
  # Returns the BER-encoded value and the criticality to use.
  def self.attribute_selection(selection)
    criticality = true
    if selection.is_a?(Hash)
      criticality = selection.fetch(:criticality, true)
      selection = selection[:attributes]
    end

    descriptions = Array(selection).map do |description|
      validate_attribute_description!(description)
      description.to_s
    end

    [descriptions.map(&:to_ber).to_ber_sequence, criticality]
  end
  private_class_method :attribute_selection

  def self.ensure_allowed!(operation, control, allowed)
    return if allowed[control]

    raise ArgumentError,
          "the #{control} control is not allowed on #{operation} operations"
  end
  private_class_method :ensure_allowed!

  def self.validate_attribute_description!(description)
    unless description.is_a?(String) || description.is_a?(Symbol)
      raise ArgumentError,
            "invalid attribute description: #{description.inspect}"
    end

    unless description.to_s.match?(ATTRIBUTE_DESCRIPTION)
      raise ArgumentError,
            "invalid attribute description: #{description.inspect}"
    end
  end
  private_class_method :validate_attribute_description!
end
