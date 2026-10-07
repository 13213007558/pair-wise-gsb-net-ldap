# -*- ruby encoding: utf-8 -*-

class Net::LDAP::Schema
  class CheckResult
    attr_reader :violations, :unchecked

    # Returns true only when no violation was found and every value could be
    # verified with locally registered schema rules. Items in unchecked do
    # not make an entry legal; they mean the client could not complete that
    # part of the offline check.

    def initialize(violations: [], unchecked: [])
      @violations = violations
      @unchecked = unchecked
    end

    def valid?
      violations.empty? && unchecked.empty?
    end
    alias verified? valid?

    def errors
      violations + unchecked
    end

    def to_h
      {
        violations: violations.map(&:to_h),
        unchecked: unchecked.map(&:to_h),
      }
    end
  end
end
