@ipv6 @rfc9915_extended
Feature: DHCPv6 relay-forward and relay-reply handling (RFC 9915)
  A server should preserve relay metadata while assigning an address to a
  client whose messages arrive through a relay agent.

  Scenario: Relayed client completes address assignment
    Given the DHCPv6 server is running
    When a relay forwards a client DHCPv6 SOLICIT
    Then the server returns a matching DHCPv6 RELAY-REPLY with an ADVERTISE
    When the relay forwards the client DHCPv6 REQUEST
    Then the server returns a matching DHCPv6 RELAY-REPLY with a leased address

  @negative
  Scenario: Malformed relay traffic is ignored without poisoning the server
    Given the DHCPv6 server is running
    When a relay sends a RELAY-FORWARD without a Relay Message option
    Then the server does not answer the malformed RELAY-FORWARD
    When a relay forwards a client DHCPv6 SOLICIT
    Then the server returns a matching DHCPv6 RELAY-REPLY with an ADVERTISE
