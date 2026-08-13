@ipv4 @conformance @relay @rfc3046
Feature: DHCPv4 server behavior behind a relay agent
  The fixture sends server-bound packets from UDP port 67 with a non-zero
  giaddr and verifies the server's reply before any client-side forwarding.

  Scenario: A relayed client completes DORA on the giaddr-selected subnet
    Given a DHCPv4 relay address exists on the alternate served subnet
    When the relay forwards a DHCPDISCOVER with circuit and remote identifiers
    Then the server returns an offer to the relay from the selected subnet
    And the offer preserves giaddr and echoes Relay Agent Information verbatim
    When the relay forwards the matching DHCPREQUEST
    Then the server returns an acknowledgement to the relay for the offered address
    And the acknowledgement preserves giaddr and echoes Relay Agent Information verbatim

  @negative
  Scenario: Relay metadata is not invented for an ordinary client
    Given the DHCP server is running
    When an ordinary DHCPv4 client completes DORA without Relay Agent Information
    Then neither server response contains Relay Agent Information
