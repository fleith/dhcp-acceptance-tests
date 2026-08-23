@ipv6 @rfc9915_extended @rfc9915_transactions
Feature: DHCPv6 transaction validation and commitment (RFC 9915)
  Malformed client transactions must be discarded without changing server state,
  while valid repeated and Rapid Commit transactions retain one durable binding.

  @negative
  Scenario: Malformed SOLICIT identifiers are discarded without poisoning discovery
    Given the DHCPv6 server is running
    When the client sends every invalid DHCPv6 SOLICIT identifier combination
    Then the server discards every malformed DHCPv6 transaction
    When a client sends a DHCPv6 SOLICIT message
    Then the client receives a DHCPv6 ADVERTISE from the server

  @negative
  Scenario: Malformed REQUEST identifiers are discarded without committing the offer
    Given the DHCPv6 server is running
    When a client sends a DHCPv6 SOLICIT message
    Then the client receives a DHCPv6 ADVERTISE from the server
    When the client sends every invalid DHCPv6 REQUEST identifier combination
    Then the server discards every malformed DHCPv6 transaction
    When the client sends a DHCPv6 REQUEST message
    Then the server responds with a DHCPv6 REPLY that finalizes the lease

  @negative
  Scenario: Malformed RELEASE identifiers cannot remove an active binding
    Given a client holds a DHCPv6 lease from the server
    When the client sends every invalid DHCPv6 RELEASE identifier combination
    Then the server discards every malformed DHCPv6 transaction
    When the client sends a DHCPv6 RENEW message
    Then the server responds with a DHCPv6 REPLY extending the lease

  @requires_dhcpv6_rapid_commit
  Scenario: Rapid Commit REPLY is backed by an active binding
    Given the DHCPv6 server is running
    When a client requests a DHCPv6 lease using Rapid Commit
    Then the server returns a Rapid Commit REPLY with a committed lease
    When the client sends a DHCPv6 RENEW message
    Then the server responds with a DHCPv6 REPLY extending the lease

  Scenario: Retransmitted REQUEST preserves one active binding
    Given a client holds a DHCPv6 lease from the server
    When the client retransmits the identical DHCPv6 REQUEST
    Then the retransmitted REQUEST returns the same binding and identifiers
    When a different client solicits the retransmitted active address
    Then the server does not advertise the retransmitted active address
