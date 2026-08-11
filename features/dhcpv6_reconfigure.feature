@ipv6 @rfc9915_extended
Feature: DHCPv6 Reconfigure signaling and validation (RFC 9915)
  The fixture cannot trigger authenticated server-initiated Reconfigure, but it
  can verify client capability signaling and mandatory server-side discards.

  Scenario: Reconfigure acceptance signaling does not disrupt address assignment
    Given the DHCPv6 server is running
    When a client requests a lease while accepting DHCPv6 Reconfigure
    Then the client receives a DHCPv6 ADVERTISE from the server
    When the client sends a DHCPv6 REQUEST message
    Then the server responds with a DHCPv6 REPLY that finalizes the lease

  @negative
  Scenario: Client-forged unauthenticated Reconfigure is ignored
    Given the DHCPv6 server is running
    When a client sends a forged unauthenticated DHCPv6 RECONFIGURE to the server
    Then the server does not answer the invalid DHCPv6 RECONFIGURE
    And the DHCPv6 server remains responsive to valid configuration requests

  @negative
  Scenario: Malformed Reconfigure is ignored without poisoning the server
    Given the DHCPv6 server is running
    When a client sends DHCPv6 RECONFIGURE without a Reconfigure Message option
    Then the server does not answer the invalid DHCPv6 RECONFIGURE
    And the DHCPv6 server remains responsive to valid configuration requests
