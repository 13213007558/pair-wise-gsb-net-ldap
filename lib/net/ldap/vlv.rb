# -*- ruby encoding: utf-8 -*-

##
# Value object returned by Net::LDAP#search_virtual_list_view. It carries
# the window of entries surrounding the target together with the list
# positioning information reported by the server's VLV response control.
class Net::LDAP
  class VLVResult
    # The entries of the returned window (before/after the target entry).
    attr_reader :entries

    # The actual position of the target entry within the sorted list, as
    # reported by the server (1-based).
    attr_reader :target_position

    # The server's current estimate of the total number of entries in the
    # sorted list.
    attr_reader :content_count

    # A Net::LDAP::VLVContext that can be handed back to
    # Net::LDAP#search_virtual_list_view (as :context) to continue moving
    # the window over the same sorted list. Nil when the server did not
    # return a context ID.
    attr_reader :context

    def initialize(entries:, target_position:, content_count:, context:)
      @entries = entries
      @target_position = target_position
      @content_count = content_count
      @context = context
    end
  end

  ##
  # A Virtual List View context, as issued by the server in a VLV response
  # control (draft-ietf-ldapext-ldapv3-vlv). A context is only meaningful
  # on the connection that created it and only for the search criteria it
  # was created with (base, scope, alias dereferencing, filter and sort
  # keys); it cannot be reused once any of those change.
  class VLVContext
    # The opaque, server-generated context ID. May be binary data.
    attr_reader :context_id

    def initialize(connection, signature, context_id)
      @connection = connection
      @signature = signature
      @context_id = context_id
    end

    # Returns true when this context may be reused on the given connection
    # with the given search-criteria signature.
    def reusable_for?(connection, signature)
      @connection.equal?(connection) && @signature == signature
    end

    # Internal: computes the signature of the search criteria a VLV context
    # is bound to. Two searches share a context only when their signatures
    # are identical.
    def self.signature(args)
      filter = args[:filter] || Net::LDAP::Filter.eq("objectClass", "*")
      filter = Net::LDAP::Filter.construct(filter) if filter.is_a?(String)

      sort = Array(args[:sort_controls]).map do |control|
        attribute, matching_rule, reverse_order = Array(control)
        [String(attribute), String(matching_rule), reverse_order == true]
      end

      [
        args[:base].to_s,
        (args[:scope] || Net::LDAP::SearchScope_WholeSubtree).to_i,
        (args[:deref] || Net::LDAP::DerefAliases_Never).to_i,
        filter.to_ber,
        sort,
      ]
    end
  end
end
