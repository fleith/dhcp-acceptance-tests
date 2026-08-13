@rfc4361
Feature: RFC 4361 node-specific DHCPv4 client identifiers
  DHCPv4 servers must use Option 61 as the client identity when it is present
  and fall back to chaddr only for legacy clients that omit the option.

  Background:
    Given the DHCP server is running

  Scenario: Type 255 IAID and DUID complete DORA
    When an RFC 4361 client completes DORA with a Type 255 IAID and DUID
    Then the server acknowledges the RFC 4361 binding

  Scenario: A stable node identifier survives a hardware-address change
    When one RFC 4361 identifier completes DORA from two hardware addresses
    Then both hardware addresses receive the same RFC 4361 binding

  Scenario: Different IAIDs distinguish interfaces on one node
    When two RFC 4361 clients use the same DUID with different IAIDs
    Then the different RFC 4361 IAIDs receive distinct bindings

  Scenario: Different DUIDs distinguish nodes using the same IAID
    When two RFC 4361 clients use the same IAID with different DUIDs
    Then the different RFC 4361 DUIDs receive distinct bindings

  Scenario: A legacy client without Option 61 falls back to chaddr
    When legacy DHCPv4 clients complete DORA without Option 61
    Then chaddr determines each legacy client binding

  @negative
  Scenario: A truncated Type 255 identifier does not poison a valid client
    When a truncated RFC 4361 identifier is followed by a valid DORA exchange
    Then the truncated RFC 4361 transaction does not receive a DHCPACK
    And the later valid RFC 4361 binding is acknowledged

  @negative
  Scenario: Client identifier changes during DORA
    When an RFC 4361 client changes its identifier between DISCOVER and REQUEST
    Then later valid exchanges keep the two RFC 4361 identifiers isolated
