@ipv6
Feature: DHCPv6 lease release (RFC 8415)
  A client should be able to release an active lease and acquire another valid lease.

  Scenario: Client releases and reacquires a DHCPv6 lease
    Given a client holds a DHCPv6 lease from the server
    When the client sends a DHCPv6 RELEASE for its active lease
    Then the server returns a successful DHCPv6 RELEASE reply
    When a client sends a DHCPv6 SOLICIT message
    Then the client receives a DHCPv6 ADVERTISE from the server
    When the client sends a DHCPv6 REQUEST message
    Then the server responds with a DHCPv6 REPLY that finalizes the lease
