# -*- ruby encoding: utf-8 -*-

class Net::LDAP::Schema::EntryValidator
  def initialize(schema, dn, attributes)
    @schema = schema
    @dn = dn
    @attributes = canonical_attributes(attributes)
  end

  def validate
    violations = []
    unchecked = []

    validate_object_classes(violations, unchecked)
    validate_content_rules(violations)
    validate_attributes(violations, unchecked)
    validate_naming(violations, unchecked)

    ::Net::LDAP::Schema::Result.new(violations, unchecked)
  end

  # Applies objectClass inheritance, DIT content rules, name forms, local
  # syntax registration, and RDN equality matching. Structural placement
  # rules (dITStructureRules and the real parent entry) are intentionally
  # outside this check.

  private

  attr_reader :schema, :dn, :attributes

  def validate_object_classes(violations, unchecked)
    names = class_names
    definitions = names.map { |name| schema.object_class(name) }

    names.each_with_index do |name, index|
      next if definitions[index]

      violations << issue('attributes.objectClass', 'unknown_object_class',
                         'objectClass ' + name + ' is not defined', name)
    end

    direct_structural = definitions.select { |definition| structural?(definition) }
    @structural_class = direct_structural.max_by do |definition|
      schema.object_class_chain(definition).count { |item| structural?(item) }
    end

    if names.any? && @structural_class.nil?
      violations << issue('attributes.objectClass', 'missing_structural_object_class',
                         'entry has no structural objectClass', names)
    end

    if @structural_class
      chain_ids = schema.object_class_chain(@structural_class).map(&:oid)
      incompatible = direct_structural.reject do |definition|
        definition.oid == @structural_class.oid || chain_ids.include?(definition.oid)
      end

      if incompatible.any?
        violations << issue('attributes.objectClass', 'multiple_structural_object_classes',
                           'entry contains incompatible structural objectClasses',
                           incompatible.map(&:raw))
      end
    end

    @resolved_classes = schema.effective_object_classes(names)
    unresolved_supertypes(@resolved_classes).each do |name|
      unchecked << issue('attributes.objectClass', 'superior_object_class_not_defined',
                         'superior objectClass ' + name + ' is not defined', name)
    end
  end

  def validate_content_rules(violations)
    @prohibited_attributes = Set.new

    applicable_rules.each do |rule|
      validate_rule_auxiliary_classes(rule, violations)

      rule.list_option('NOT').each do |name|
        next unless attribute_present?(name)

        definition, _chain = schema.resolve_attribute(name)
        identifier = definition&.oid || name.to_s.downcase
        next if @prohibited_attributes.include?(identifier)

        @prohibited_attributes << identifier
        violations << issue('attributes.' + attribute_path(name), 'attribute_not_allowed',
                           'attribute ' + (definition&.name || name) + ' is prohibited by a DIT content rule',
                           rule.raw)
      end
    end
  end

  def validate_rule_auxiliary_classes(rule, violations)
    allowed = rule.list_option('AUX')
    return if allowed.empty?

    @resolved_classes.select { |item| item.boolean_option('AUX') }.each do |item|
      next if allowed.include?(item.oid) || allowed.any? { |name| item.attribute?(name) }

      violations << issue('attributes.objectClass', 'auxiliary_class_not_allowed',
                         'auxiliary objectClass ' + item.name + ' is not allowed by a DIT content rule',
                         rule.raw)
    end
  end

  def validate_attributes(violations, unchecked)
    must = attribute_rules('MUST')
    may = attribute_rules('MAY')
    allowed = Set.new(must.keys + may.keys)

    must.each do |name, bases|
      next if attribute_present?(name)

      definition, _chain = schema.resolve_attribute(name)
      violations << issue('attributes.' + attribute_path(name), 'missing_required_attribute',
                         'attribute ' + (definition&.name || name) + ' is required', bases)
    end

    attributes.each do |key, values|
      next if key == :objectclass

      definition, chain = schema.resolve_attribute(key)
      unless definition
        violations << issue('attributes.' + key.to_s, 'unknown_attribute',
                           'attribute ' + key.to_s + ' is not defined', key)
        next
      end

      next if @prohibited_attributes&.include?(definition.oid)

      unless allowed.include?(definition.oid)
        violations << issue('attributes.' + key.to_s, 'attribute_not_allowed',
                           'attribute ' + definition.name + ' is not permitted by objectClasses or DIT content rules',
                           definition.raw)
        next
      end

      unresolved_attribute_supertype(definition, unchecked)
      validate_values(definition, chain, key, values, violations, unchecked)
    end
  end

  def validate_values(definition, chain, key, values, violations, unchecked)
    values = Array(values)
    if schema.single_valued?(chain) && values.length > 1
      violations << issue('attributes.' + key.to_s, 'multiple_values_for_single_value_attribute',
                         'attribute ' + definition.name + ' is single-valued', definition.raw)
    end

    syntax_oid, bound = effective_syntax(chain)
    unless syntax_oid
      unchecked << issue('attributes.' + key.to_s, 'syntax_not_registered',
                         'attribute ' + definition.name + ' has no registered syntax', definition.raw)
      return
    end

    unless ::Net::LDAP::Schema::SyntaxRegistry.syntax_registered?(syntax_oid)
      unchecked << issue('attributes.' + key.to_s, 'syntax_not_registered',
                         'syntax ' + syntax_oid + ' is not registered for value checking', definition.raw)
      return
    end

    values.each_with_index do |value, index|
      unless ::Net::LDAP::Schema::SyntaxRegistry.valid_syntax?(syntax_oid, value)
        violations << issue('attributes.' + key.to_s + '[' + index.to_s + ']', 'invalid_syntax_value',
                           'value does not conform to syntax ' + syntax_oid, definition.raw)
        next
      end

      if bound && ::Net::LDAP::Schema::SyntaxRegistry.length(syntax_oid, value) > bound
        violations << issue('attributes.' + key.to_s + '[' + index.to_s + ']', 'syntax_length_exceeded',
                           'value exceeds syntax length bound ' + bound.to_s, definition.raw)
      end
    end
  end

  def validate_naming(violations, unchecked)
    rdns = parse_rdn
    unless rdns
      violations << issue('dn.rdn', 'invalid_dn', 'DN is badly formed', dn)
      return
    end

    forms = applicable_name_forms
    return if forms.empty?

    rdn_oids = rdns.map { |name, _value| resolve_oid(name) }.compact
    matched = forms.find do |form|
      required = form.list_option('MUST').map { |name| resolve_oid(name) }.compact
      allowed = (form.list_option('MUST') + form.list_option('MAY')).map { |name| resolve_oid(name) }.compact
      (required - rdn_oids).empty? && rdn_oids.all? { |oid| allowed.include?(oid) }
    end

    unless matched
      violations << issue('dn.rdn', 'rdn_attribute_not_allowed_by_name_form',
                         'RDN attribute is not a naming attribute for the structural objectClass',
                         forms.map(&:raw))
    end

    check_rdn_presence(rdns, violations)
    check_rdn_values(rdns, violations, unchecked)
  end

  def check_rdn_presence(rdns, violations)
    rdns.each do |name, _value|
      next if attribute_present?(name)

      definition, _chain = schema.resolve_attribute(name)
      violations << issue('dn.rdn', 'rdn_attribute_missing',
                         'RDN attribute ' + (definition&.name || name) + ' must also appear in attributes',
                         definition&.raw || name)
    end
  end

  def check_rdn_values(rdns, violations, unchecked)
    rdns.each do |name, rdn_value|
      definition, chain = schema.resolve_attribute(name)
      next unless definition

      matching_rule = schema.effective_matching_rule(chain)
      unless matching_rule
        unchecked << issue('dn.rdn.' + attribute_path(name), 'equality_matching_rule_not_registered',
                           'attribute ' + definition.name + ' has no equality matching rule', definition.raw)
        next
      end

      unless ::Net::LDAP::Schema::SyntaxRegistry.equality_matcher_registered?(matching_rule)
        unchecked << issue('dn.rdn.' + attribute_path(name), 'equality_matching_rule_not_registered',
                           'equality matching rule ' + matching_rule + ' is not registered', definition.raw)
        next
      end

      values = attribute_values(name)
      next unless values
      next if values.any? { |value| ::Net::LDAP::Schema::SyntaxRegistry.equal?(matching_rule, value, rdn_value) }

      violations << issue('dn.rdn.' + attribute_path(name), 'rdn_value_not_found',
                         'RDN value has no matching attribute value under the equality matching rule',
                         definition.raw)
    end
  end

  def applicable_rules
    return [] unless @structural_class

    rule = schema.dit_content_rule(@structural_class.oid)
    rule ? [rule] : []
  end

  def attribute_rules(option)
    rules = Hash.new { |hash, key| hash[key] = [] }

    @resolved_classes.each do |object_class|
      object_class.list_option(option).each do |name|
        rules[resolve_oid(name) || name.to_s.downcase] << object_class.raw
      end
    end

    applicable_rules.each do |rule|
      rule.list_option(option).each do |name|
        rules[resolve_oid(name) || name.to_s.downcase] << rule.raw
      end
    end

    rules
  end

  def effective_syntax(chain)
    syntax_definition = chain.find { |item| item.value_option('SYNTAX') }
    return [nil, nil] unless syntax_definition

    token = syntax_definition.value_option('SYNTAX').to_s
    oid, bound = token.split('{', 2)
    [oid, bound && bound.to_i]
  end

  def unresolved_supertypes(classes)
    classes.flat_map do |object_class|
      object_class.sup.reject { |name| schema.object_class(name) }
    end.uniq
  end

  def unresolved_attribute_supertype(definition, unchecked)
    definition.sup.each do |name|
      next if schema.attribute_type(name)

      unchecked << issue('attributes.' + attribute_path(definition.oid),
                         'superior_attribute_type_not_defined',
                         'superior attribute type ' + name + ' is not defined', definition.raw)
    end
  end

  def parse_rdn
    first = dn.to_s.split(/(?<!\\),/, 2).first.to_s
    first.split(/(?<!\\)\+/).map do |ava|
      name, value = ava.split('=', 2)
      raise Net::LDAP::InvalidDNError, 'DN badly formed' unless name && !value.nil? && !value.empty?

      definition, _chain = schema.resolve_attribute(name.strip)
      [(definition&.oid || name.strip.downcase), unescape_rdn_value(value)]
    end
  rescue Net::LDAP::InvalidDNError
    nil
  end

  def unescape_rdn_value(value)
    value = value.strip
    return [value[1..]].pack('H2').force_encoding(Encoding::BINARY) if value.start_with?('#')

    value.gsub(/\\([0-9a-fA-F]{2})/) { [Regexp.last_match(1)].pack('H2') }
         .gsub(/\\(.)/) { Regexp.last_match(1) }
  end

  def class_names
    Array(attributes[:objectclass]).map { |name| name.to_s.downcase }.uniq
  end

  def canonical_attributes(attributes)
    result = {}
    attributes.each do |name, value|
      key = ::Net::LDAP::Entry.attribute_name(name)
      next if key == :dn

      definition = schema.attribute_type(key)
      identifier = definition ? definition.oid : key
      result[identifier] ||= [key, []]
      result[identifier][1].concat(Array(value))
    end
    result.each_value.map { |key, values| [key, values] }.to_h
  end

  def attribute_present?(name)
    !attribute_values(name).nil?
  end

  def attribute_values(name)
    definition, _chain = schema.resolve_attribute(name)
    keys = definition ? attribute_keys(definition) : [::Net::LDAP::Entry.attribute_name(name)]
    key = keys.find { |candidate| attributes.key?(candidate) }
    key && attributes[key]
  end

  def attribute_keys(definition)
    ([definition.oid] + definition.names).map { |name| ::Net::LDAP::Entry.attribute_name(name) }
  end

  def attribute_path(name)
    definition, _chain = schema.resolve_attribute(name)
    definition&.names&.first || name.to_s
  end

  def resolve_oid(name)
    definition, _chain = schema.resolve_attribute(name)
    definition&.oid
  end

  def structural?(definition)
    definition && !definition.boolean_option('ABSTRACT') && !definition.boolean_option('AUX')
  end

  def applicable_name_forms
    return [] unless @structural_class

    schema.object_class_chain(@structural_class).flat_map do |item|
      schema.name_forms_for(item.oid)
    end.uniq
  end

  def issue(path, code, message, basis)
    ::Net::LDAP::Schema::Issue.new(path, code, message, basis)
  end
end
