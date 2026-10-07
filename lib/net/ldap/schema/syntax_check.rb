# -*- ruby encoding: utf-8 -*-

class Net::LDAP::Schema
  module SyntaxCheck
    REGISTERED_SYNTAXES = {
      '1.3.6.1.4.1.1466.115.121.1.7' => :boolean,
      '1.3.6.1.4.1.1466.115.121.1.12' => :distinguished_name,
      '1.3.6.1.4.1.1466.115.121.1.15' => :directory_string,
      '1.3.6.1.4.1.1466.115.121.1.26' => :ia5_string,
      '1.3.6.1.4.1.1466.115.121.1.27' => :integer,
      '1.3.6.1.4.1.1466.115.121.1.36' => :numeric_string,
      '1.3.6.1.4.1.1466.115.121.1.38' => :oid,
      '1.3.6.1.4.1.1466.115.121.1.40' => :octet_string,
    }.freeze

    def check_syntax(definition, requested_name, values, violations, unchecked)
      effective = schema.attribute_chain(definition).find(&:syntax)
      unless effective
        unchecked << syntax_finding(definition, requested_name, nil,
                                   'No syntax is registered on the attribute type chain.')
        return
      end

      syntax_type = REGISTERED_SYNTAXES[effective.syntax]
      unless syntax_type
        unchecked << syntax_finding(effective, requested_name, effective.syntax,
                                   'Syntax OID is not recognized by the local checker.')
        return
      end

      values.each_with_index do |value, index|
        message = syntax_error(syntax_type, effective, value)
        next unless message

        violations << Finding.new(
          code: :invalid_attribute_syntax,
          message: message,
          location: "entry.attributes.#{requested_name}[#{index}]",
          basis: effective.basis('SYNTAX', value: value, syntax: effective.syntax)
        )
      end
    end

    private

    def syntax_finding(definition, requested_name, syntax, message)
      Finding.new(
        code: :unregistered_syntax,
        message: message,
        location: "entry.attributes.#{requested_name}",
        basis: definition.basis('SYNTAX', syntax: syntax, status: 'unchecked')
      )
    end

    def syntax_error(type, definition, value)
      text = value.to_s
      valid = case type
              when :boolean then text.match?(/\A(?:TRUE|FALSE)\z/i)
              when :integer then text.match?(/\A[+-]?\d+\z/)
              when :numeric_string then text.match?(/\A(?:[0-9]| )+\z/)
              when :oid then valid_oid?(text)
              when :ia5_string then text.bytes.all? { |byte| byte <= 127 }
              when :directory_string then valid_utf8?(text)
              when :distinguished_name then valid_dn_syntax?(text)
              when :octet_string then true
              else false
              end

      return 'Value does not match the registered syntax.' unless valid

      syntax_length_error(definition, text)
    end

    def syntax_length_error(definition, text)
      return nil unless definition.syntax_length && text.bytesize > definition.syntax_length

      "Value exceeds the registered syntax length bound of #{definition.syntax_length} bytes."
    end

    def valid_oid?(value)
      value.match?(/\A(?:[0-9]+(?:\.[0-9]+)*|[A-Za-z][A-Za-z0-9-]*)\z/)
    end

    def valid_utf8?(value)
      value.encode('UTF-8', invalid: :replace, undef: :replace).valid_encoding?
    rescue EncodingError
      false
    end

    def valid_dn_syntax?(value)
      DNParser.rdn(value)
      true
    rescue Net::LDAP::InvalidDNError
      false
    end
  end
end
