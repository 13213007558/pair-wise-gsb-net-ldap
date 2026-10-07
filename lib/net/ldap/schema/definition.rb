# -*- ruby encoding: utf-8 -*-

class Net::LDAP::Schema::Definition
  attr_reader :oid, :names, :sup, :raw, :options

  def initialize(kind, raw)
    tree = ::Net::LDAP::Schema::SchemaParser.parse_description(raw)
    @kind = kind
    @raw = raw
    @oid = tree.shift
    @names = []
    @sup = []
    @options = {}
    parse_options(tree)
  end

  def name
    names.first || oid
  end

  def attribute?(name)
    oid == name.to_s.downcase || names.map(&:downcase).include?(name.to_s.downcase)
  end

  def boolean_option(name)
    options.key?(name)
  end

  def list_option(name)
    Array(options[name]).flatten
  end

  def value_option(name)
    options[name]
  end

  def structural_object_class
    value_option('OC')
  end

  private

  def parse_options(tree)
    until tree.empty?
      keyword = tree.shift.to_s.upcase
      if ::Net::LDAP::Schema::SchemaParser.flags.include?(keyword)
        options[keyword] = true
        next
      end

      value = tree.shift
      case keyword
      when 'NAME' then @names = Array(value).flatten
      when 'SUP' then @sup = Array(value).flatten.map(&:downcase)
      else options[keyword] = value
      end
    end
  end
end
