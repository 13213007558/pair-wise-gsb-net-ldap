# -*- ruby encoding: utf-8 -*-

require 'stringio'

class Net::LDAP::Schema::SchemaParser
  KEYWORDS = %w[
    ABSTRACT APPLIES AUX DESC EQUALITY FORM MUST MAY NAME NAMEFORM NOT
    OBSOLETE OC RULES STRUCTURAL SUP SINGLE-VALUE SYNTAX USAGE
  ].freeze
  FLAGS = %w[ABSTRACT AUX OBSOLETE SINGLE-VALUE STRUCTURAL].freeze

  def self.parse_description(description)
    tokens = tokenize(description)
    tree, index = parse_list(tokens, 0)
    raise ArgumentError, "invalid schema description: #{description}" unless index == tokens.length
    tree
  end

  def self.tokenize(description)
    tokens = []
    buffer = StringIO.new
    index = 0
    quote = false

    flush = proc do
      token = buffer.string
      tokens << token unless token.empty?
      buffer = StringIO.new
    end

    while index < description.length
      char = description[index]

      if char == '\\' && index.succ < description.length
        buffer << description[index] << description[index.succ]
        index += 2
        next
      end

      if char == "'"
        quote = !quote
        index += 1
        next
      end

      if !quote && (char =~ /\s/ || ['(', ')', '$'].include?(char))
        flush.call
        tokens << char unless char =~ /\s/
        index += 1
        next
      end

      buffer << char
      index += 1
    end

    raise ArgumentError, 'invalid schema description' if quote

    flush.call
    tokens
  end

  def self.parse_list(tokens, index)
    raise ArgumentError, 'invalid schema description' unless tokens[index] == '('

    values = []
    index += 1

    while index < tokens.length && tokens[index] != ')'
      token = tokens[index]

      if token == '('
        value, index = parse_list(tokens, index)
        values << value
      elsif token == '$'
        index += 1
      else
        values << decode_token(token)
        index += 1
      end
    end

    raise ArgumentError, 'invalid schema description' unless tokens[index] == ')'
    [values, index.succ]
  end

  def self.flags
    FLAGS
  end

  def self.decode_token(token)
    if token.start_with?('"')
      token[1..-2].gsub(/\\(.)/) { Regexp.last_match(1) }
    elsif token.start_with?('\\')
      token.gsub(/\\(.)/) { Regexp.last_match(1) }
    elsif token =~ /\A\d+(?:\.\d+)*\z/
      token
    elsif KEYWORDS.include?(token.upcase)
      token.upcase
    else
      token.downcase
    end
  end
end
