@ipv6
Feature: DHCPv6 lease lifetime validation (RFC 9915)
  The server should return consistent renewal and address lifetimes for a lease.

  Scenario: DHCPv6 lease includes expected IA_NA and address lifetimes
    Given the DHCPv6 server is running
    When a client sends a DHCPv6 SOLICIT message
    Then the client receives a DHCPv6 ADVERTISE from the server
    When the client sends a DHCPv6 REQUEST message
    Then the server responds with a DHCPv6 REPLY that finalizes the lease
    And the DHCPv6 REPLY has the expected IA_NA timers
    And the DHCPv6 REPLY has the expected IA Address lifetimes
