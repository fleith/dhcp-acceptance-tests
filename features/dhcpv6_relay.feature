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

  Scenario Outline: Relay hop-count metadata is preserved at valid boundaries
    Given the DHCPv6 server is running
    When a relay forwards a client DHCPv6 SOLICIT with hop-count <hop_count>
    Then the server returns a matching DHCPv6 RELAY-REPLY with hop-count <hop_count>

    Examples:
      | hop_count |
      | 0         |
      | 7         |
      | 8         |

  Scenario: A nested relay path is returned in reverse encapsulation order
    Given the DHCPv6 server is running
    When two relays with distinct Interface-IDs forward a client DHCPv6 SOLICIT
    Then the server returns an ADVERTISE through both original relay layers
    And each RELAY-REPLY layer preserves its Interface-ID

  @negative @kea3_malformed_relay_crash
  Scenario: A missing Relay Message option is ignored without poisoning the server
    Given the DHCPv6 server is running
    When a relay sends a RELAY-FORWARD without a Relay Message option
    Then the server does not answer the malformed RELAY-FORWARD
    When a relay forwards a client DHCPv6 SOLICIT
    Then the server returns a matching DHCPv6 RELAY-REPLY with an ADVERTISE

  @negative @kea3_malformed_relay_crash
  Scenario: A truncated relay metadata option is ignored without poisoning the server
    Given the DHCPv6 server is running
    When a relay sends a RELAY-FORWARD with a truncated Interface-ID option
    Then the server does not answer the malformed RELAY-FORWARD
    When a relay forwards a client DHCPv6 SOLICIT
    Then the server returns a matching DHCPv6 RELAY-REPLY with an ADVERTISE
