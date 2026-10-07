# -*- ruby encoding: utf-8 -*-

class Net::LDAP::Schema::SyntaxRegistry
  PRINTABLE_STRING = /\A[A-Za-z0-9 '()+,.\-\/:=?]*\z/.freeze
  OID = /\A(?:\d+(?:\.\d+)*|[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*)\z/i.freeze
  BIT_STRING = /\A'[01]*'B\z/.freeze

  SYNTAXES = {
    '1.3.6.1.4.1.1466.115.121.1.5' => :bit_string?,
    '1.3.6.1.4.1.1466.115.121.1.7' => :boolean?,
    '1.3.6.1.4.1.1466.115.121.1.27' => :integer?,
    '1.3.6.1.4.1.1466.115.121.1.12' => :distinguished_name?,
    '1.3.6.1.4.1.1466.115.121.1.15' => :directory_string?,
    '1.3.6.1.4.1.1466.115.121.1.22' => :printable_string?,
    '1.3.6.1.4.1.1466.115.121.1.26' => :ia5_string?,
    '1.3.6.1.4.1.1466.115.121.1.38' => :oid?,
    '1.3.6.1.4.1.1466.115.121.1.40' => :octet_string?,
  }.freeze

  CASE_INSENSITIVE_CHECKERS = [
    :case_ignore_string?,
    :numeric_string?,
  ].freeze

  MATCHING_RULES = {
    '2.5.13.0' => :oid?,
    'objectidentifiermatch' => :oid?,
    '2.5.13.1' => :distinguished_name?,
    'distinguishednamematch' => :distinguished_name?,
    '2.5.13.2' => :case_ignore_string?,
    'caseignorematch' => :case_ignore_string?,
    '2.5.13.3' => :case_exact_string?,
    'caseexactmatch' => :case_exact_string?,
    '2.5.13.7' => :integer?,
    'integermatch' => :integer?,
    '2.5.13.8' => :numeric_string?,
    'numericstringmatch' => :numeric_string?,
    '2.5.13.21' => :boolean?,
    'booleanmatch' => :boolean?,
  }.freeze

  def self.syntax_registered?(oid)
    SYNTAXES.key?(oid.to_s)
  end

  def self.valid_syntax?(oid, value)
    checker = SYNTAXES[oid.to_s]
    checker ? public_send(checker, value) : nil
  end

  def self.length(oid, value)
    string = value.to_s
    oid.to_s == '1.3.6.1.4.1.1466.115.121.1.40' ? string.bytesize : string.length
  end

  def self.equality_matcher_registered?(oid)
    MATCHING_RULES.key?(oid.to_s.downcase)
  end

  def self.equal?(matching_rule, left, right)
    checker = MATCHING_RULES[matching_rule.to_s.downcase]
    return nil unless checker
    public_send(checker, left) && public_send(checker, right) &&
      normalize(left, checker) == normalize(right, checker)
  end

  def self.bit_string?(value)
    value.to_s.match?(BIT_STRING)
  end

  def self.boolean?(value)
    %w[TRUE FALSE].include?(value.to_s.upcase)
  end

  def self.integer?(value)
    value.to_s.match?(/\A-?\d+\z/)
  end

  def self.numeric_string?(value)
    value.to_s.match?(/\A\d+\z/)
  end

  def self.distinguished_name?(value)
    Net::LDAP::DN.new(value.to_s).to_a
    true
  rescue Net::LDAP::InvalidDNError
    false
  end

  def self.directory_string?(value)
    string = value.to_s.dup.force_encoding(Encoding::UTF_8)
    string.valid_encoding? && string.each_codepoint.none?(&:zero?)
  end

  def self.case_ignore_string?(value)
    directory_string?(value)
  end

  def self.case_exact_string?(value)
    directory_string?(value)
  end

  def self.printable_string?(value)
    value.to_s.match?(PRINTABLE_STRING)
  end

  def self.ia5_string?(value)
    value.to_s.dup.force_encoding(Encoding::BINARY).match?(/\A[\x00-\x7F]*\z/n)
  end

  def self.oid?(value)
    value.to_s.match?(OID)
  end

  def self.octet_string?(_value)
    true
  end

  def self.normalize(value, checker)
    result = value.to_s
    result = result.downcase if CASE_INSENSITIVE_CHECKERS.include?(checker)
    result = result.gsub(/\s+/, ' ').strip if CASE_INSENSITIVE_CHECKERS.include?(checker)
    result
  end
end
