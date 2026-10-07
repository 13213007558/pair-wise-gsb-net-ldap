# -*- ruby encoding: utf-8 -*-

class Net::LDAP::Schema
  Finding = Struct.new(:code, :message, :location, :basis, keyword_init: true) do
    def to_h
      {
        code: code,
        message: message,
        location: location,
        basis: basis,
      }
    end
  end
end
