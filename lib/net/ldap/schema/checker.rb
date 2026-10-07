# -*- ruby encoding: utf-8 -*-

class Net::LDAP::Schema
  class Checker
    include SyntaxCheck

    EQUALITY_MATCHERS = {
      '2.5.13.0' => ->(value) { value.to_s.strip.downcase },
      'objectidentifiermatch' => ->(value) { value.to_s.strip.downcase },
      '2.5.13.1' => ->(value) { value.to_s.downcase },
      'distinguishednamematch' => ->(value) { value.to_s.downcase },
      '2.5.13.2' => ->(value) { normalize_case_ignore(value) },
      'caseignorematch' => ->(value) { normalize_case_ignore(value) },
      '2.5.13.3' => ->(value) { value.to_s.upcase },
      'booleanmatch' => ->(value) { value.to_s.upcase },
      '2.5.13.5' => ->(value) { value.to_s },
      'caseexactmatch' => ->(value) { value.to_s },
      '2.5.13.8' => ->(value) { value.to_s.delete('- ').upcase },
      'numericstringmatch' => ->(value) { value.to_s.delete(' ') },
      '2.5.13.14' => ->(value) { value.to_s.to_i.to_s },
      'integermatch' => ->(value) { value.to_s.to_i.to_s },
      '2.5.13.22' => ->(value) { value.to_s.b },
      'octetstringmatch' => ->(value) { value.to_s.b },
      '2.5.13.24' => ->(value) { value.to_s.downcase },
      'caseignoreia5match' => ->(value) { normalize_case_ignore(value) },
    }.freeze

    def self.normalize_case_ignore(value)
      value.to_s.gsub(/\s+/, ' ').strip.downcase
    end

    def initialize(schema)
      @schema = schema
    end

    attr_reader :schema

    def check(dn, attributes)
      groups, object_class_ids = prepare_attributes(attributes)
      violations = []
      unchecked = []
      rdn = parse_rdn(dn, violations)

      class_defs, structural_class, class_violations = resolve_classes(object_class_ids)
      violations.concat(class_violations)

      rules = effective_rules(class_defs, structural_class)
      check_auxiliary_content_rules(class_defs, structural_class, violations)
      check_required_attributes(groups, rules, violations)
      check_attributes(groups, rules, violations, unchecked)
      check_rdn(rdn, groups, structural_class, violations, unchecked) if rdn

      CheckResult.new(violations: violations, unchecked: unchecked)
    end

    private

    def prepare_attributes(attributes)
      groups = Hash.new { |hash, key| hash[key] = {} }
      object_class_ids = []

      Array(attributes).each do |key, raw_values|
        original_name = key.to_s.split(';', 2).first
        name = original_name.downcase
        values = Kernel::Array(raw_values)

        if name == 'objectclass'
          object_class_ids.concat(values.map(&:to_s))
        else
          definition = @schema.resolve_attribute(name)
          identifier = definition ? definition.oid : "unknown:#{name}"
          groups[identifier][original_name] ||= []
          groups[identifier][original_name].concat(values)
        end
      end

      [groups, object_class_ids.map(&:downcase)]
    end

    def parse_rdn(dn, violations)
      DNParser.rdn(dn)
    rescue Net::LDAP::InvalidDNError
      violations << Finding.new(
        code: :invalid_dn_syntax,
        message: 'Target DN does not have a valid RDN.',
        location: 'dn.rdn',
        basis: { dn: dn.to_s }
      )
      nil
    end

    def resolve_classes(object_class_ids)
      definitions = []
      violations = []

      object_class_ids.uniq.each do |identifier|
        definition = @schema.resolve_object_class(identifier)
        unless definition
          violations << undefined_object_class_finding(identifier)
          next
        end
        definitions << definition
      end

      [definitions.uniq, structural_class(definitions, violations), violations]
    end

    def undefined_object_class_finding(identifier)
      Finding.new(
        code: :undefined_object_class,
        message: "Object class #{identifier} is not defined in the subschema.",
        location: "entry.object_classes.#{identifier}",
        basis: { requested_object_class: identifier }
      )
    end

    def structural_class(definitions, violations)
      structural = definitions.uniq.select { |definition| definition.class_kind == :structural }
      roots = structural.reject do |definition|
        @schema.object_class_chain(definition).any? do |ancestor|
          ancestor.oid != definition.oid && structural.map(&:oid).include?(ancestor.oid)
        end
      end.uniq

      record_structural_class_violation(roots, violations)
      roots.first
    end

    def record_structural_class_violation(roots, violations)
      if roots.empty?
        violations << structural_class_finding(:missing_structural_object_class,
                                             'Entry does not list a concrete structural object class.',
                                             {})
      elsif roots.length > 1
        violations << structural_class_finding(:multiple_structural_object_classes,
                                             'Entry lists multiple independent structural object classes.',
                                             structural_object_classes: roots.map(&:oid))
      end
    end

    def structural_class_finding(code, message, basis)
      Finding.new(
        code: code,
        message: message,
        location: 'entry.object_classes',
        basis: basis
      )
    end

    def effective_rules(class_defs, structural_class)
      direct_chains = class_defs.map { |definition| @schema.object_class_chain(definition) }
      structural_chain = structural_class ? @schema.object_class_chain(structural_class) : []
      chains = (direct_chains + [structural_chain]).select(&:any?).uniq
      content_rules = content_rules_for(chains.flatten.uniq, structural_chain)
      all_chains = chains.flatten + content_rules

      {
        must: union_oids(all_chains, :must, ['objectclass']),
        may: union_oids(all_chains, :may),
        not: union_oids(content_rules, :not),
        definitions: all_chains.uniq,
      }
    end

    def content_rules_for(class_defs, structural_chain)
      identifiers = class_defs.map(&:oid) + structural_chain.map(&:oid)
      identifiers.uniq.filter_map { |identifier| @schema.dit_content_rules[identifier] }
    end

    def check_auxiliary_content_rules(class_defs, structural_class, violations)
      return unless structural_class

      rule = @schema.dit_content_rules[structural_class.oid]
      return unless rule && rule.aux.any?

      class_defs.select { |definition| definition.class_kind == :auxiliary }.map(&:oid).uniq.each do |oid|
        next if rule.aux.include?(oid)

        violations << Finding.new(
          code: :auxiliary_object_class_not_allowed,
          message: "Auxiliary object class #{oid} is not allowed by the DIT content rule.",
          location: "entry.object_classes.#{oid}",
          basis: rule.basis('AUX', object_class: oid)
        )
      end
    end

    def union_oids(definitions, field, implicit = [])
      (implicit + definitions.flat_map { |definition| Array(definition[field]) }).uniq
    end

    def check_required_attributes(groups, rules, violations)
      return if rules[:definitions].empty?

      rules[:must].each do |oid|
        next if oid == 'objectclass'
        next if groups.key?(oid)

        violations << required_finding(oid, rules[:definitions])
      end
    end

    def required_finding(oid, definitions)
      definition = @schema.attribute_types[oid] || @schema.resolve_attribute(oid)
      name = definition ? definition.primary_name : oid
      source = definitions.find { |rule| Array(rule.must).include?(oid) }

      Finding.new(
        code: :missing_required_attribute,
        message: "Required attribute #{name} is absent.",
        location: "entry.attributes.#{name}",
        basis: (source || definition || unknown_definition(oid, :attribute_type)).basis('MUST', attribute: oid)
      )
    end

    def check_attributes(groups, rules, violations, unchecked)
      groups.each do |identifier, aliases|
        definition = @schema.attribute_types[identifier]
        requested_name = aliases.keys.first
        values = aliases.values.flatten
        location = "entry.attributes.#{requested_name}"

        unless definition
          violations << undefined_attribute_finding(requested_name, location)
          next
        end

        check_attribute_usage(definition, requested_name, location, rules, violations)
        check_single_value(definition, requested_name, values, violations)
        check_syntax(definition, requested_name, values, violations, unchecked)
      end
    end

    def undefined_attribute_finding(name, location)
      Finding.new(
        code: :undefined_attribute,
        message: "Attribute #{name} is not defined in the subschema.",
        location: location,
        basis: { requested_attribute: name }
      )
    end

    def check_attribute_usage(definition, requested_name, location, rules, violations)
      attribute_oids = @schema.attribute_chain(definition).map(&:oid)

      if attribute_oids.any? { |oid| rules[:not].include?(oid) }
        rule = rules[:definitions].find do |item|
          item.kind == :content_rule && attribute_oids.any? { |oid| item.not.include?(oid) }
        end
        violations << Finding.new(
          code: :attribute_not_allowed,
          message: "Attribute #{requested_name} is prohibited by a DIT content rule.",
          location: location,
          basis: rule.basis('NOT', attribute: definition.oid)
        )
      elsif !allowed?(definition, rules)
        violations << Finding.new(
          code: :attribute_not_allowed,
          message: "Attribute #{requested_name} is not required or allowed by the object class chain.",
          location: location,
          basis: attribute_usage_basis(definition.oid, rules)
        )
      end
    end

    def allowed?(definition, rules)
      oids = @schema.attribute_chain(definition).map(&:oid)
      oids.any? { |oid| rules[:must].include?(oid) || rules[:may].include?(oid) }
    end

    def attribute_usage_basis(oid, rules)
      source = rules[:definitions].find do |definition|
        definition.must.include?(oid) || definition.may.include?(oid)
      end
      source ||= unknown_definition('unknown', :object_class)
      source.basis('MUST/MAY', attribute: oid)
    end

    def unknown_definition(oid, kind)
      Definition.new(kind: kind, oid: oid, names: [], sup: [], raw: nil)
    end

    def check_single_value(definition, requested_name, values, violations)
      return unless @schema.attribute_chain(definition).any?(&:single_value)
      return unless values.length > 1

      violations << Finding.new(
        code: :single_value_violation,
        message: "Attribute #{requested_name} is single-valued.",
        location: "entry.attributes.#{requested_name}",
        basis: definition.basis('SINGLE-VALUE', value_count: values.length)
      )
    end

    def check_rdn(rdn, groups, structural_class, violations, unchecked)
      forms = matching_name_forms(structural_class)
      rdn_attributes = rdn.map { |ava| @schema.resolve_attribute(ava.attribute)&.oid }.compact

      forms.each do |form|
        form.must.each do |required_oid|
          next if rdn_attributes.include?(required_oid)

          violations << Finding.new(
            code: :rdn_missing_required_name_attribute,
            message: 'RDN does not contain an attribute required by the applicable name form.',
            location: 'dn.rdn',
            basis: form.basis('MUST', attribute: required_oid)
          )
        end
      end

      rdn.each do |ava|
        definition = @schema.resolve_attribute(ava.attribute)
        location = "dn.rdn.#{ava.attribute}"

        unless definition
          violations << Finding.new(
            code: :undefined_rdn_attribute,
            message: "RDN attribute #{ava.attribute} is not defined in the subschema.",
            location: location,
            basis: { requested_attribute: ava.attribute }
          )
          next
        end

        check_rdn_attribute(definition, ava, groups, forms, location, violations, unchecked)
      end
    end

    def matching_name_forms(structural_class)
      return [] unless structural_class

      @schema.object_class_chain(structural_class).each do |definition|
        forms = @schema.name_forms_for(definition.oid)
        return forms if forms.any?
      end

      []
    end

    def check_rdn_attribute(definition, ava, groups, forms, location, violations, unchecked)
      form = forms.find { |candidate| (candidate.must + candidate.may).include?(definition.oid) }

      if forms.any? && form.nil?
        violations << Finding.new(
          code: :rdn_attribute_not_allowed_by_name_form,
          message: "RDN attribute #{ava.attribute} is not permitted by the applicable name form.",
          location: location,
          basis: forms.first.basis('MUST/MAY', attribute: definition.oid)
        )
      end

      values = groups[definition.oid]&.values&.flatten || []
      matcher = equality_matcher(definition)
      unless matcher && values.any? { |value| equality_match?(matcher, value, ava.value) }
        if matcher
          violations << Finding.new(
            code: :rdn_value_not_in_entry,
            message: "RDN value for #{ava.attribute} does not match an entry attribute value.",
            location: location,
            basis: definition.basis('EQUALITY', value: ava.value)
          )
        else
          unchecked << Finding.new(
            code: :unregistered_equality_matching,
            message: 'Cannot verify RDN equality without a known equality matching rule.',
            location: location,
            basis: definition.basis('EQUALITY', value: ava.value, status: 'unchecked')
          )
        end
      end
    end

    def equality_match?(matcher, entry_value, rdn_value)
      matcher.call(entry_value) == matcher.call(rdn_value)
    end

    def equality_matcher(definition)
      effective = @schema.attribute_chain(definition).find(&:equality)
      return nil unless effective

      EQUALITY_MATCHERS[effective.equality.downcase]
    end
  end
end
