# -*- ruby encoding: utf-8 -*-

class Net::LDAP::Schema
  Definition = Struct.new(
    :kind,
    :oid,
    :names,
    :sup,
    :object_class,
    :class_kind,
    :must,
    :may,
    :not,
    :aux,
    :equality,
    :syntax,
    :syntax_length,
    :single_value,
    :obsolete,
    :raw,
    keyword_init: true
  ) do
    def primary_name
      names.first || oid
    end

    def basis(rule, extra = {})
      {
        kind: kind,
        oid: oid,
        names: names,
        rule: rule,
        raw: raw,
      }.merge(extra)
    end
  end
end
