# -*- ruby encoding: utf-8 -*-

class Net::LDAP::Schema
  class DNParser
    AttributeValueAssertion = Struct.new(:attribute, :value, keyword_init: true)

    def self.rdn(dn)
      parser = new(dn)
      rdn, index = parser.send(:parse_component, 0)
      parser.send(:parse_remainder, index)
      rdn
    end

    def initialize(dn)
      @dn = dn.to_s
    end

    private

    def parse_remainder(index)
      index = skip_spaces(@dn, index)
      return if index == @dn.length

      raise Net::LDAP::InvalidDNError, 'DN badly formed' unless @dn[index] == ',' || @dn[index] == ';'

      next_component_index = skip_spaces(@dn, index + 1)
      _component, next_index = parse_component(next_component_index)
      parse_remainder(next_index)
    end

    def parse_component(index)
      raise Net::LDAP::InvalidDNError, 'DN badly formed' if index >= @dn.length

      avas, index = read_attribute_value_assertions(@dn, index)
      raise Net::LDAP::InvalidDNError, 'DN badly formed' if avas.empty?

      [avas, index]
    end

    def read_attribute_value_assertions(string, index)
      avas = []

      loop do
        attribute, index = read_token(string, index, /[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)*/)
        raise Net::LDAP::InvalidDNError, 'DN badly formed' unless attribute

        index = skip_spaces(string, index)
        raise Net::LDAP::InvalidDNError, 'DN badly formed' unless string[index] == '='

        value, index = read_value(string, index + 1)
        avas << AttributeValueAssertion.new(attribute: attribute.downcase, value: value)

        index = skip_spaces(string, index)
        return [avas, index] if index >= string.length
        raise Net::LDAP::InvalidDNError, 'DN badly formed' unless string[index] == ',' || string[index] == '+' || string[index] == ';'

        separator = string[index]
        return [avas, index] unless separator == '+'
        index = skip_spaces(string, index + 1)
      end
    end

    def read_token(string, index, pattern)
      index = skip_spaces(string, index)
      match = string.match(pattern, index)
      return nil unless match && match.begin(0) == index

      [match[0], match.end(0)]
    end

    def read_value(string, index)
      index = skip_spaces(string, index)

      if string[index] == '#'
        read_hex_value(string, index + 1)
      elsif string[index] == '"'
        read_quoted_value(string, index + 1)
      else
        read_unquoted_value(string, index)
      end
    end

    def read_hex_value(string, index)
      value = +''
      while hex_pair?(string, index)
        value << string[index, 2].to_i(16).chr
        index += 2
      end
      raise Net::LDAP::InvalidDNError, 'DN badly formed' if value.empty?

      [value.b, index]
    end

    def read_quoted_value(string, index)
      value = +''

      while index < string.length
        char = string[index]

        if char == '"'
          return [value, index + 1]
        elsif char == '\\'
          decoded, index = read_escape(string, index)
          value << decoded
        else
          value << char
          index += 1
        end
      end

      raise Net::LDAP::InvalidDNError, 'DN badly formed'
    end

    def read_unquoted_value(string, index)
      value = +''
      started = false
      trailing_spaces = 0

      while index < string.length
        char = string[index]

        if char == ',' || char == '+' || char == ';'
          value = value.delete_suffix(' ' * trailing_spaces)
          break
        elsif char == '\\'
          decoded, index = read_escape(string, index)
          value << decoded
          trailing_spaces = 0
          started = true
        elsif char == '#' && !started
          raise Net::LDAP::InvalidDNError, 'DN badly formed'
        elsif char == ' ' && started
          trailing_spaces += 1
          value << char
          index += 1
        else
          value << char
          trailing_spaces = 0
          started = true
          index += 1
        end
      end

      raise Net::LDAP::InvalidDNError, 'DN badly formed' unless started

      [value.delete_suffix(' ' * trailing_spaces), index]
    end

    def read_escape(string, index)
      escaped = string[index + 1]

      if escaped && escaped =~ /[0-9A-Fa-f]/
        second = string[index + 2]
        raise Net::LDAP::InvalidDNError, 'DN badly formed' unless second && second =~ /[0-9A-Fa-f]/

        ["#{escaped}#{second}".to_i(16).chr, index + 3]
      else
        [escaped.to_s, index + 2]
      end
    end

    def hex_pair?(string, index)
      string[index] && string[index + 1] &&
        string[index] =~ /[0-9A-Fa-f]/ &&
        string[index + 1] =~ /[0-9A-Fa-f]/
    end

    def skip_spaces(string, index)
      index += 1 while string[index] == ' '
      index
    end
  end
end
