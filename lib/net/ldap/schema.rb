# -*- ruby encoding: utf-8 -*-

require 'strscan'
require_relative 'dn'
require_relative 'schema/finding'
require_relative 'schema/definition'
require_relative 'schema/definition_parser'
require_relative 'schema/dn_parser'
require_relative 'schema/check_result'
require_relative 'schema/syntax_check'
require_relative 'schema/checker'

class Net::LDAP::Schema
  class ParseError < Net::LDAP::Error; end

  ATTRIBUTE_TYPES_KEY = :attributetypes
  OBJECT_CLASSES_KEY = :objectclasses
  CONTENT_RULES_KEY = :ditcontentrules
  NAME_FORMS_KEY = :nameforms

  SOURCE_KEYS = {
    ATTRIBUTE_TYPES_KEY => :attribute_type,
    OBJECT_CLASSES_KEY => :object_class,
    CONTENT_RULES_KEY => :content_rule,
    NAME_FORMS_KEY => :name_form,
  }.freeze

  attr_reader :attribute_types, :object_classes, :dit_content_rules, :name_forms

  ##
  # Parsed offline representation of an LDAP subschema entry. It resolves
  # attribute aliases, SUP inheritance, object-class chains, DIT content
  # rules, and name forms without contacting a directory server.

  def self.from(source)
    new(source)
  end

  def self.from_entry(entry)
    new(entry)
  end

  def self.check(subschema, dn, attributes)
    new(subschema).check(dn, attributes)
  end

  def initialize(source)
    source = normalize_source(source)

    @attribute_types = {}
    @object_classes = {}
    @dit_content_rules = {}
    @name_forms = {}
    @attribute_index = {}
    @object_class_index = {}
    @name_form_index = Hash.new { |hash, key| hash[key] = [] }

    parse(source)
    build_definition_indexes
    resolve_references
    build_name_form_index
  end

  ##
  # Checks an entry against the parsed subschema. +attributes+ may be a Hash,
  # or omitted entirely when +dn+ is a Net::LDAP::Entry. Hard schema
  # violations are reported separately from values that cannot be proven
  # valid locally, such as unregistered syntaxes and equality matching rules.
  def check(dn, attributes = nil)
    attributes, dn = attributes_from_entry(dn, attributes)
    Checker.new(self).check(dn, attributes)
  end
  alias check_entry check

  def resolve_attribute(identifier)
    return nil unless identifier

    name = identifier.to_s.split(';', 2).first.to_s.downcase
    @attribute_index[name]
  end

  def resolve_object_class(identifier)
    @object_class_index[identifier.to_s.downcase]
  end

  def attribute_chain(definition, seen = {})
    return [] unless definition
    return [] if seen[definition.oid]

    seen[definition.oid] = true
    [definition] + definition.sup.flat_map do |sup|
      attribute_chain(@attribute_types[sup], seen)
    end
  end

  def object_class_chain(definition, seen = {})
    return [] unless definition
    return [] if seen[definition.oid]

    seen[definition.oid] = true
    [definition] + definition.sup.flat_map do |sup|
      object_class_chain(@object_classes[sup], seen)
    end
  end

  def name_forms_for(object_class_oid)
    @name_form_index[object_class_oid]
  end

  private

  def normalize_source(source)
    if source.is_a?(Net::LDAP::Entry)
      source.to_h.reject { |key, _| key == :dn }
    elsif source.is_a?(Hash)
      source
    else
      raise ArgumentError, 'subschema must be a Net::LDAP::Entry or Hash'
    end
  end

  def parse(source)
    SOURCE_KEYS.each do |key, kind|
      Array(source[key] || source[key.to_s]).flatten.compact.each do |raw|
        definition = DefinitionParser.parse(raw, kind)
        collection_for(kind)[definition.oid] = definition
      end
    end
  end

  def collection_for(kind)
    case kind
    when :attribute_type then @attribute_types
    when :object_class then @object_classes
    when :content_rule then @dit_content_rules
    when :name_form then @name_forms
    end
  end

  def build_definition_indexes
    index_definitions(@attribute_types, @attribute_index)
    index_definitions(@object_classes, @object_class_index)
  end

  def build_name_form_index
    @name_forms.each_value do |form|
      @name_form_index[form.object_class] << form if form.object_class
    end
  end

  def index_definitions(definitions, index)
    definitions.each_value do |definition|
      index[definition.oid] = definition
      definition.names.each { |name| index[name.downcase] = definition }
    end
  end

  def resolve_references
    all_definitions.each do |definition|
      if definition.kind == :content_rule
        definition.sup = definition.sup.map { |identifier| identifier.downcase }
      else
        definition.sup = definition.sup.map { |identifier| resolve_reference(identifier) }
        definition.object_class = resolve_reference(definition.object_class) if definition.object_class
      end

      [:must, :may, :not, :aux].each do |field|
        definition[field] = definition[field].map { |identifier| resolve_reference(identifier) }
      end

      definition.equality = normalize_matching_rule(definition.equality) if definition.equality
    end
  end

  def all_definitions
    @attribute_types.values + @object_classes.values +
      @dit_content_rules.values + @name_forms.values
  end

  def resolve_reference(identifier)
    @attribute_index[identifier]&.oid ||
      @object_class_index[identifier]&.oid ||
      identifier
  end

  def normalize_matching_rule(identifier)
    Checker::EQUALITY_MATCHERS.key?(identifier.downcase) ? identifier.downcase : identifier
  end

  def attributes_from_entry(dn, attributes)
    if attributes.nil? && dn.is_a?(Net::LDAP::Entry)
      [dn.to_h.reject { |key| key == :dn }, dn.dn]
    else
      [attributes || {}, dn]
    end
  end
end
