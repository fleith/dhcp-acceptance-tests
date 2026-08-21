@ipv4 @conformance @relay @rfc3046
Feature: DHCPv4 server behavior behind a relay agent
  The fixture sends server-bound packets from UDP port 67 with a non-zero
  giaddr and verifies the server's reply before any client-side forwarding.

  @ipv4_should_next
  Scenario: A relayed client completes DORA on the giaddr-selected subnet
    Given a DHCPv4 relay address exists on the alternate served subnet
    When the relay forwards a DHCPDISCOVER with circuit and remote identifiers
    Then the server returns an offer to the relay from the selected subnet
    And the offer preserves giaddr and echoes Relay Agent Information verbatim
    When the relay forwards the matching DHCPREQUEST
    Then the server returns an acknowledgement to the relay for the offered address
    And the acknowledgement preserves giaddr and echoes Relay Agent Information verbatim
    And both relay responses place Relay Agent Information last

  @ipv4_should_next
  Scenario: A unicast renewal carrying Relay Agent Information is handled
    Given the DHCP server is running
    When an ordinary DHCPv4 client completes DORA without Relay Agent Information
    And the bound client renews directly by unicast with Relay Agent Information
    Then the unicast renewal is acknowledged with Relay Agent Information unchanged

  @ipv4_should_next
  Scenario: Circuit ID policy uses opaque exact matching
    Given a DHCPv4 relay address exists on the alternate served subnet
    When relayed clients use exact and lookalike opaque Circuit IDs
    Then only the exact Circuit ID receives the configured relay policy

  @negative
  Scenario: Relay metadata is not invented for an ordinary client
    Given the DHCP server is running
    When an ordinary DHCPv4 client completes DORA without Relay Agent Information
    Then neither server response contains Relay Agent Information

  @must_gap
  Scenario: Relay metadata never moves into overloaded BOOTP fields
    Given a DHCPv4 relay address exists on the alternate served subnet
    When the relay completes DORA with an oversized requested option
    Then both relayed responses preserve the oversized option fragments
    And both relayed responses keep Relay Agent Information in the main option area
