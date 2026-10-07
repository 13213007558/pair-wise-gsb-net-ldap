require_relative 'test_helper'

class TestSchema < Test::Unit::TestCase
  def test_reports_inheritance_content_rule_and_rdn_violations
    result = validate(invalid_attributes)

    assert_equal %w[attribute_not_allowed missing_required_attribute rdn_attribute_missing],
                 result.violations.map(&:code).sort
    assert_empty result.unchecked
  end

  def test_aliases_resolve_to_same_definitions
    result = validate(
      objectClass: ['subClassAlias'],
      'forbidden-a' => 'present',
    )

    assert_equal %w[attribute_not_allowed missing_required_attribute rdn_attribute_missing],
                 result.violations.map(&:code).sort
    paths = result.violations.map(&:path)
    assert_include paths, 'attributes.forbiddenattr'
    assert_include paths, 'attributes.requiredattr'
    assert_include paths, 'dn.rdn'
    assert result.violations.flat_map { |issue| Array(issue.basis) }.grep(/requiredAttr/).first
  end

  def test_valid_alias_and_rdn_equality
    result = validate(
      objectClass: ['subClassAlias'],
      'required-a' => ' Required Value ',
      'naming-c' => 'RDN Value',
    )

    assert_empty result.violations.map(&:code)
    assert_empty result.unchecked.map(&:code)
  end

  def test_single_value_constraint_is_inherited
    schema = schema_entry(
      attribute_types: [single_value_parent_attribute, single_value_attribute],
      object_classes: [top_object_class, structural_object_class],
      dit_content_rules: [],
      name_forms: [],
    )

    result = Net::LDAP::Schema.check_entry(
      schema,
      'single=one,dc=example,dc=org',
      objectClass: ['structural'],
      single: ['one', 'two'],
    )

    assert_include result.violations.map(&:code),
                   'multiple_values_for_single_value_attribute'
  end

  def test_unregistered_syntax_is_unchecked_not_valid
    schema = schema_entry(
      attribute_types: [unregistered_syntax_attribute],
      object_classes: [top_object_class, structural_object_class],
      dit_content_rules: [],
      name_forms: [],
    )

    result = Net::LDAP::Schema.check_entry(
      schema,
      'custom=one,dc=example,dc=org',
      objectClass: ['structural'],
      custom: 'anything',
    )

    assert_empty result.violations
    assert_equal ['syntax_not_registered'], result.unchecked.map(&:code)
    refute result.valid?
  end

  def test_registered_syntax_value_violation_is_reported
    schema = schema_entry(
      attribute_types: [integer_attribute],
      object_classes: [top_object_class, structural_object_class],
      dit_content_rules: [],
      name_forms: [],
    )

    result = Net::LDAP::Schema.check_entry(
      schema,
      'custom=one,dc=example,dc=org',
      objectClass: ['structural'],
      custom: 'not-an-integer',
    )

    assert_equal ['invalid_syntax_value'], result.violations.map(&:code)
    assert_empty result.unchecked
  end

  private

  def validate(attributes)
    Net::LDAP::Schema.check_entry(schema, 'naming-c=RDN Value,dc=example,dc=org', attributes)
  end

  def invalid_attributes
    {
      objectClass: ['subClass'],
      forbiddenAttr: 'present',
    }
  end

  def schema
    schema_entry(
      attribute_types: attribute_types,
      object_classes: object_classes,
      dit_content_rules: dit_content_rules,
      name_forms: name_forms,
    )
  end

  def schema_entry(attribute_types:, object_classes:, dit_content_rules:, name_forms:)
    entry = Net::LDAP::Entry.new
    entry[:attributetypes] = attribute_types
    entry[:objectclasses] = object_classes
    entry[:ditcontentrules] = dit_content_rules
    entry[:nameforms] = name_forms
    entry
  end

  def attribute_types
    [
      "( 1.1 NAME ( 'requiredAttr' 'required-a' ) EQUALITY caseIgnoreMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
      "( 1.2 NAME ( 'forbiddenAttr' 'forbidden-a' ) EQUALITY caseIgnoreMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
      "( 1.3 NAME ( 'namingAttr' 'naming-c' ) EQUALITY caseIgnoreMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    ]
  end

  def object_classes
    [
      top_object_class,
      "( 2.1 NAME 'baseClass' SUP top STRUCTURAL MUST requiredAttr )",
      "( 2.2 NAME ( 'subClass' 'subClassAlias' ) SUP baseClass STRUCTURAL
        MAY ( forbiddenAttr $ namingAttr ) )",
    ]
  end

  def top_object_class
    "( 2.0 NAME 'top' ABSTRACT )"
  end

  def structural_object_class
    "( 3.1 NAME 'structural' SUP top STRUCTURAL MAY ( single $ custom ) )"
  end

  def dit_content_rules
    [
      "( 2.2 NAME 'subClassRule' NOT forbiddenAttr )",
    ]
  end

  def name_forms
    [
      "( 4.1 NAME 'subClassForm' OC subClass MUST namingAttr )",
    ]
  end

  def single_value_parent_attribute
    "( 5.0 NAME 'singleParent' SINGLE-VALUE
      EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
  end

  def single_value_attribute
    "( 5.1 NAME 'single' SUP singleParent )"
  end

  def unregistered_syntax_attribute
    "( 6.1 NAME 'custom' EQUALITY caseIgnoreMatch SYNTAX 9.9.9.9 )"
  end

  def integer_attribute
    "( 6.2 NAME 'custom' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )"
  end
end
