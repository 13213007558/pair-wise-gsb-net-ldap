# -*- ruby encoding: utf-8 -*-

require 'set'
require_relative 'dn'

class Net::LDAP
  class Schema; end
end

class Net::LDAP::Schema
  Issue = Struct.new(:path, :code, :message, :basis)
  Result = Struct.new(:violations, :unchecked) do
    def valid?
      violations.empty? && unchecked.empty?
    end

    def errors
      violations
    end
  end

  SCHEMA_ATTRIBUTES = {
    :attributetypes => :attribute_types,
    :objectclasses => :object_classes,
    :ditcontentrules => :dit_content_rules,
    :nameforms => :name_forms,
  }.freeze

  attr_reader :attribute_types, :object_classes, :dit_content_rules, :name_forms

  def self.check_entry(subschema_entry, dn, attributes)
    new(subschema_entry).check_entry(dn, attributes)
  end

  # Parses the four schema entry attributes required for offline entry
  # validation. Use Net::LDAP::Schema.check_entry for the complete check.

  def initialize(subschema_entry)
    @attribute_types = {}
    @object_classes = {}
    @dit_content_rules = {}
    @name_forms = []
    parse(subschema_entry)
  end

  def check_entry(dn, attributes = {})
    EntryValidator.new(self, dn, attributes).validate
  end

  def attribute_type(name)
    attribute_types[normalize(name)]
  end

  def object_class(name)
    object_classes[normalize(name)]
  end

  def dit_content_rule(name)
    dit_content_rules[normalize(name)]
  end

  def name_forms_for(object_class_name)
    object_class = object_class(object_class_name)
    return [] unless object_class

    chain = object_class_chain(object_class)
    name_forms.select do |form|
      chain.any? { |item| item.oid == form.structural_object_class || item.names.include?(form.structural_object_class) }
    end
  end

  def resolve_attribute(name)
    definition = attribute_type(name)
    return [nil, []] unless definition

    [definition, attribute_chain(definition).uniq(&:oid)]
  end

  def object_class_chain(definition, seen = Set.new)
    return [] if definition.nil? || seen.include?(definition.oid)
    seen << definition.oid
    [definition] + definition.sup.flat_map { |name| object_class_chain(object_class(name), seen) }
  end

  def effective_object_classes(classes)
    resolved = []
    seen = Set.new

    classes.each do |name|
      definition = object_class(name)
      next unless definition
      object_class_chain(definition).each do |item|
        unless seen.include?(item.oid)
          resolved << item
          seen << item.oid
        end
      end
    end

    resolved
  end

  def effective_matching_rule(chain)
    rule_definition = chain.find { |definition| definition.value_option('EQUALITY') }
    rule_definition && rule_definition.value_option('EQUALITY').to_s
  end

  def single_valued?(chain)
    chain.any? { |item| item.boolean_option('SINGLE-VALUE') }
  end

  def structural_object_class(classes)
    definitions = classes.map { |name| object_class(name) }.compact
    structural = definitions.select { |definition| kind_of?(definition, 'STRUCTURAL') }
    return structural.first if structural.empty?

    structural.max_by do |definition|
      object_class_chain(definition).count { |item| kind_of?(item, 'STRUCTURAL') }
    end
  end

  def kind_of?(definition, kind)
    if kind == 'STRUCTURAL'
      !definition.boolean_option('ABSTRACT') && !definition.boolean_option('AUX')
    else
      definition.boolean_option(kind)
    end
  end

  private

  def parse(subschema_entry)
    source = schema_source(subschema_entry)

    SCHEMA_ATTRIBUTES.each do |source_name, collection_name|
      Array(source[source_name]).each do |raw|
        add_definition(collection_name, raw)
      end
    end
  end

  def schema_source(subschema_entry)
    if subschema_entry.respond_to?(:each)
      source = {}
      subschema_entry.each do |key, value|
        source[::Net::LDAP::Entry.attribute_name(key)] = value unless key == :dn
      end
      source
    else
      {}
    end
  end

  def add_definition(collection_name, raw)
    definition = Definition.new(collection_name, raw.to_s)

    case collection_name
    when :attribute_types then index(attribute_types, definition)
    when :object_classes then index(object_classes, definition)
    when :dit_content_rules then index(dit_content_rules, definition)
    when :name_forms then name_forms << definition
    end
  end

  def index(collection, definition)
    collection[definition.oid.downcase] = definition
    definition.names.each { |name| collection[name.downcase] = definition }
  end

  def attribute_chain(definition, seen = Set.new)
    return [] if definition.nil? || seen.include?(definition.oid)
    seen << definition.oid
    [definition] + definition.sup.flat_map { |name| attribute_chain(attribute_type(name), seen) }
  end

  def normalize(name)
    name.to_s.downcase
  end
end

require_relative 'schema/definition'
require_relative 'schema/schema_parser'
require_relative 'schema/syntax_registry'
require_relative 'schema/entry_validator'
