# -*- ruby encoding: utf-8 -*-

require_relative 'test_helper'

class TestSchema < Test::Unit::TestCase
  SYNTAX = '1.3.6.1.4.1.1466.115.121.1.15'

  ATTRIBUTE_TYPES = [
    "( 1.1 NAME 'requiredName' EQUALITY caseIgnoreMatch SYNTAX #{SYNTAX} )",
    "( 1.2 NAME ( 'forbiddenName' 'forbiddenAlias' ) EQUALITY caseIgnoreMatch SYNTAX #{SYNTAX} )",
    "( 1.3 NAME ( 'rdnName' 'rdnAlias' ) EQUALITY caseIgnoreMatch SYNTAX #{SYNTAX} )",
    "( 1.4 NAME 'cn' EQUALITY caseIgnoreMatch SYNTAX #{SYNTAX} )",
  ].freeze

  OBJECT_CLASSES = [
    "( 2.1 NAME 'top' ABSTRACT )",
    "( 2.2 NAME 'parent' SUP top STRUCTURAL MUST requiredName MAY ( forbiddenName rdnName cn ) )",
    "( 2.3 NAME 'child' SUP parent STRUCTURAL )",
  ].freeze

  CONTENT_RULES = [
    '( 2.3 NOT forbiddenName )',
  ].freeze

  NAME_FORMS = [
    %q{( 3.1 NAME 'childForm' OC 2.3 MUST cn )},
  ].freeze

  def schema(overrides = {})
    defaults = {
      attributetypes: ATTRIBUTE_TYPES,
      objectclasses: OBJECT_CLASSES,
      ditcontentrules: CONTENT_RULES,
      nameforms: NAME_FORMS,
    }

    combined = defaults.merge(overrides) do |_key, default, override|
      Array(default) + Array(override)
    end

    Net::LDAP::Schema.new(combined)
  end

  def test_reports_inheritance_content_rule_and_rdn_violations_with_aliases
    result = schema.check(
      'rdnAlias=Third+cn=Third,ou=people,dc=example,dc=com',
      'objectClass' => ['CHILD'],
      'forbiddenAlias' => ['blocked'],
      'rdnAlias' => ['Third'],
      'cn' => ['Third'],
    )

    codes = result.violations.map(&:code)
    assert_equal [:missing_required_attribute, :attribute_not_allowed,
                  :rdn_attribute_not_allowed_by_name_form], codes

    forbidden = result.violations[1]
    assert_equal 'entry.attributes.forbiddenAlias', forbidden.location
    assert_equal '2.3', forbidden.basis[:oid]
    assert_equal '1.2', forbidden.basis[:attribute]
    assert_equal :content_rule, forbidden.basis[:kind]

    rdn = result.violations[2]
    assert_equal 'dn.rdn.rdnalias', rdn.location
    assert_equal '1.3', rdn.basis[:attribute]
  end

  def test_alias_resolves_to_same_single_value_definition
    attributes = {
      attributetypes: [
        "( 1.5 NAME ( 'givenName' 'gn' ) SUP 1.2 SINGLE-VALUE )",
      ],
    }

    result = schema(attributes).check(
      'cn=Example,dc=example,dc=com',
      'objectClass' => ['parent'],
      'requiredName' => ['present'],
      'cn' => ['Example'],
      'givenName' => ['first'],
      'gn' => ['second'],
      'forbiddenName' => ['allowed for parent'],
    )

    assert_equal [:single_value_violation], result.violations.map(&:code)
    assert_equal '1.5', result.violations.first.basis[:oid]
  end

  def test_registered_syntax_is_validated_and_unknown_syntax_is_unchecked
    checked_schema = schema({
      attributetypes: [
        "( 1.6 NAME 'booleanValue' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
        "( 1.7 NAME 'mysteryValue' SYNTAX 9.9.9.9.1 )",
      ] + ATTRIBUTE_TYPES,
      objectclasses: [
        "( 2.4 NAME 'schemaThing' SUP parent STRUCTURAL MUST ( booleanValue mysteryValue ) )",
      ] + OBJECT_CLASSES,
    })

    result = checked_schema.check(
      'cn=Example,dc=example,dc=com',
      'objectClass' => ['schemaThing'],
      'requiredName' => ['present'],
      'booleanValue' => ['maybe'],
      'mysteryValue' => ['anything'],
      'cn' => ['Example'],
    )

    assert_equal [:invalid_attribute_syntax], result.violations.map(&:code)
    assert_equal [:unregistered_syntax], result.unchecked.map(&:code)
    assert_equal false, result.valid?
    assert_equal false, result.verified?
  end

  def test_rdn_value_uses_equality_matching_separately_from_name_resolution
    result = schema.check(
      'cn=  EXAMPLE  ,dc=example,dc=com',
      'objectClass' => ['parent'],
      'requiredName' => ['present'],
      'forbiddenName' => ['allowed for parent'],
      'cn' => ['example'],
    )

    assert_empty result.violations
  end

  def test_syntax_and_single_value_constraints_are_inherited_from_sup
    inherited_schema = schema({
      attributetypes: [
        "( 1.8 NAME 'inheritedValue' SUP 1.4 )",
      ],
      objectclasses: [
        "( 2.5 NAME 'inheritanceThing' SUP parent STRUCTURAL MUST inheritedValue )",
      ],
    })

    result = inherited_schema.check(
      'cn=Example,dc=example,dc=com',
      'objectClass' => ['inheritanceThing'],
      'requiredName' => ['present'],
      'inheritedValue' => ['value'],
      'cn' => ['Example'],
    )

    assert_empty result.violations
    assert_empty result.unchecked
  end

  def test_unknown_equality_matching_rule_remains_unchecked
    unknown_schema = schema({
      attributetypes: [
        "( 1.9 NAME 'mysteryMatch' EQUALITY customMatch SYNTAX #{SYNTAX} )",
      ],
      objectclasses: [
        "( 2.6 NAME 'mysteryFormThing' SUP parent STRUCTURAL MAY mysteryMatch )",
      ],
    })

    result = unknown_schema.check(
      'mysteryMatch=value,dc=example,dc=com',
      'objectClass' => ['mysteryFormThing'],
      'requiredName' => ['present'],
      'mysteryMatch' => ['different'],
    )

    assert_empty result.violations
    assert_equal [:unregistered_equality_matching], result.unchecked.map(&:code)
  end

  def test_accepts_subschema_and_entry_objects
    subschema = Net::LDAP::Entry.new.tap do |entry|
      entry[:attributetypes] = ATTRIBUTE_TYPES
      entry[:objectclasses] = OBJECT_CLASSES
      entry[:ditcontentrules] = CONTENT_RULES
      entry[:nameforms] = NAME_FORMS
    end
    target = Net::LDAP::Entry.new('cn=Example,dc=example,dc=com').tap do |entry|
      entry[:objectClass] = ['child']
      entry[:cn] = ['Example']
    end

    result = Net::LDAP::Schema.from_entry(subschema).check_entry(target)

    assert_includes result.violations.map(&:code), :missing_required_attribute
  end

  def test_full_dn_must_be_valid_when_checking_rdn
    result = schema.check(
      'cn=Example,',
      'objectClass' => ['parent'],
      'requiredName' => ['present'],
      'cn' => ['Example'],
    )

    assert_equal [:invalid_dn_syntax], result.violations.map(&:code)
  end

  def test_content_rule_limits_auxiliary_object_classes
    auxiliary_schema = schema({
      attributetypes: [
        "( 1.10 NAME 'auxName' EQUALITY caseIgnoreMatch SYNTAX #{SYNTAX} )",
      ],
      objectclasses: [
        "( 2.7 NAME 'allowedAux' SUP top AUXILIARY MAY auxName )",
        "( 2.8 NAME 'blockedAux' SUP top AUXILIARY )",
      ],
      ditcontentrules: [
        '( 2.3 AUX 2.7 NOT forbiddenName )',
      ],
    })

    result = auxiliary_schema.check(
      'cn=Example,ou=people,dc=example,dc=com',
      'objectClass' => ['child', 'blockedAux'],
      'cn' => ['Example'],
    )

    assert_includes result.violations.map(&:code), :auxiliary_object_class_not_allowed
  end
end
