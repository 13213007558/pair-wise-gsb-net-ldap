# -*- ruby encoding: utf-8 -*-

class Net::LDAP::Schema
  class DefinitionParser
    LIST_KEYWORDS = %i[must may not aux].freeze

    def self.parse(raw, kind)
      new(raw, kind).parse
    end

    def initialize(raw, kind)
      @raw = raw.to_s
      @kind = kind
      @tokens = tokenize(@raw)
    end

    def parse
      tokens = definition_tokens
      index = 1
      oid = tokens.first
      raise Schema::ParseError, "Missing OID in: #{@raw}" unless oid
      definition = base_definition(oid)

      while index < tokens.length
        keyword = tokens[index].to_s.downcase.to_sym
        index = consume_keyword(definition, keyword, tokens, index + 1)
      end

      normalize_definition(definition)
    end

    private

    def tokenize(string)
      tokens = []
      scanner = StringScanner.new(string)

      until scanner.eos?
        scanner.scan(/\s+/)
        break if scanner.eos?

        token = scanner.scan(/[()$]/) ||
                 scanner.scan(/'[^']*'/) ||
                 scanner.scan(/[^\s()'$]+/)
        raise Schema::ParseError, "Malformed schema description: #{string}" unless token

        tokens << token
      end

      tokens
    end

    def definition_tokens
      opening = @tokens.index('(')
      return @tokens unless opening

      depth = 0
      opening.upto(@tokens.length - 1) do |index|
        depth += 1 if @tokens[index] == '('
        depth -= 1 if @tokens[index] == ')'
        next unless depth.zero?

        return @tokens[opening + 1...index]
      end

      raise Schema::ParseError, "Unbalanced parentheses in: #{@raw}"
    end

    def base_definition(oid)
      Definition.new(
        kind: @kind,
        oid: oid.to_s.downcase,
        names: [],
        sup: @kind == :object_class ? [] : nil,
        class_kind: @kind == :object_class ? :structural : nil,
        must: [],
        may: [],
        not: [],
        aux: [],
        object_class: nil,
        single_value: false,
        obsolete: false,
        raw: @raw
      )
    end

    def consume_keyword(definition, keyword, tokens, index)
      case keyword
      when :name
        definition.names, index = read_names(tokens, index)
      when :desc then return skip_value(tokens, index)
      when :obsolete then definition.obsolete = true
      when :sup
        definition.sup, index = read_oid_list(tokens, index)
      when :equality
        definition.equality, index = read_scalar_oid(tokens, index)
      when :syntax then read_syntax(definition, tokens, index)
      when :'single-value' then definition.single_value = true
      when :abstract, :auxiliary, :structural
        definition.class_kind = keyword.to_s.downcase.to_sym
      when :oc
        object_classes, index = read_oid_list(tokens, index)
        definition.object_class = object_classes.first
      when *LIST_KEYWORDS then set_list(definition, keyword, tokens, index)
      when :usage then return skip_value(tokens, index)
      else
        return skip_extension(tokens, index) if keyword.to_s.start_with?('X-')
      end

      index
    end

    def read_names(tokens, index)
      values, next_index = read_values(tokens, index)
      [values.map { |value| unquote(value).to_s }, next_index]
    end

    def read_oid_list(tokens, index)
      values, next_index = read_values(tokens, index)
      [values.map { |value| normalize_oid(value) }, next_index]
    end

    def read_scalar_oid(tokens, index)
      values, next_index = read_values(tokens, index)
      [normalize_oid(values.first), next_index]
    end

    def set_list(definition, keyword, tokens, index)
      values, next_index = read_values(tokens, index)
      definition[keyword] = values.map { |value| normalize_oid(value) }
      next_index
    end

    def read_syntax(definition, tokens, index)
      value = tokens.fetch(index)
      oid, bound = value.to_s.split('{', 2)
      definition.syntax = oid.downcase
      definition.syntax_length = bound.to_s.delete('}').to_i if bound
      index + 1
    end

    def read_values(tokens, index)
      return [[unquote(tokens[index])], index + 1] unless tokens[index] == '('

      values = []
      index += 1
      until tokens[index] == ')'
        raise Schema::ParseError, "Unbalanced list in: #{@raw}" if index >= tokens.length

        values << unquote(tokens[index]) unless tokens[index] == '$'
        index += 1
      end

      [values, index + 1]
    end

    def skip_value(tokens, index)
      tokens[index] == '(' ? skip_list(tokens, index) : index + 1
    end

    def skip_extension(tokens, index)
      return index unless index < tokens.length

      return skip_list(tokens, index) if tokens[index] == '('

      index + 1
    end

    def skip_list(tokens, index)
      depth = 0
      while index < tokens.length
        depth += 1 if tokens[index] == '('
        depth -= 1 if tokens[index] == ')'
        index += 1
        break if depth.zero?
      end
      index
    end

    def unquote(value)
      value.to_s.sub(/\A'/, '').sub(/'\z/, '')
    end

    def normalize_oid(value)
      unquote(value).to_s.downcase
    end

    def normalize_definition(definition)
      definition.sup = Array(definition.sup).compact
      definition.must ||= []
      definition.may ||= []
      definition.not ||= []
      definition.aux ||= []
      definition.names ||= []
      definition
    end
  end
end
