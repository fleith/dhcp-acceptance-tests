@ipv6
Feature: DHCPv6 lease release (RFC 8415)
  A released address should become available for assignment to another client.

  Scenario: Released DHCPv6 address can be assigned to another client
    Given a client holds a DHCPv6 lease from the server
    When the client sends a DHCPv6 RELEASE for its active lease
    Then the server returns a successful DHCPv6 RELEASE reply
    When a different client solicits the released DHCPv6 address
    Then the server advertises the released DHCPv6 address
    When the client sends a DHCPv6 REQUEST message
    Then the server responds with a DHCPv6 REPLY that finalizes the lease
