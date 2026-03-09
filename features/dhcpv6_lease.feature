@ipv6
Feature: DHCPv6 lease assignment and renewal (RFC 8415)
  The server should assign and renew IPv6 leases for a stateful DHCPv6 client.

  Scenario: Client obtains a new DHCPv6 lease
    Given the DHCPv6 server is running
    When a client sends a DHCPv6 SOLICIT message
    Then the client receives a DHCPv6 ADVERTISE from the server
    When the client sends a DHCPv6 REQUEST message
    Then the server responds with a DHCPv6 REPLY that finalizes the lease

  Scenario: Client renews an active DHCPv6 lease
    Given a client holds a DHCPv6 lease from the server
    When the client sends a DHCPv6 RENEW message
    Then the server responds with a DHCPv6 REPLY extending the lease