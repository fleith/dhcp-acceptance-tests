@ipv6 @rfc9915_reply_closure @negative
Feature: DHCPv6 IA_NA ownership protection (RFC 9915)
  A client must not receive another client's active address through a forged
  REQUEST or REBIND, regardless of whether the server rejects the transaction
  or assigns a different, newly owned resource.

  Scenario: Forged REQUEST cannot claim another client's active IA_NA
    Given a client holds a DHCPv6 lease from the server
    When a different DUID sends a DHCPv6 REQUEST for the active IA_NA
    Then the forged IA_NA response does not assign the victim address
    When the client sends a DHCPv6 RENEW message
    Then the server responds with a DHCPv6 REPLY extending the lease

  @rfc9915_rebind_ownership
  Scenario: Forged REBIND cannot claim another client's active IA_NA
    Given a client holds a DHCPv6 lease from the server
    When a different DUID sends a DHCPv6 REBIND for the active IA_NA
    Then the forged IA_NA response does not assign the victim address
    When the client sends a DHCPv6 RENEW message
    Then the server responds with a DHCPv6 REPLY extending the lease
