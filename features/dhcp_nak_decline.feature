Feature: DHCPNAK and DHCPDECLINE handling (RFC 2131 §3.1.4, §3.1.5)
  As a network administrator
  I want the DHCP server to reject invalid requests and handle address conflicts
  So that IP assignments remain consistent and conflict-free

  @negative
  Scenario: Server handles invalid request outside served subnet
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER message
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    When the client sends a DHCPREQUEST for an address outside the server's subnet
    Then the server responds with a DHCPNAK or stays silent

  @negative
  Scenario: Server does not re-offer an address the client declined
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER message
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    When the client sends a DHCPDECLINE for the offered address
    Then the server offers a different address on the next DHCPDISCOVER

  @negative @capability @requires_admin_notification @ipv4_observability
  Scenario: Server records an administrative notification for DHCPDECLINE
    Given the DHCP server is running
    And the DHCPv4 administrative event log is observable
    When a client sends a DHCPDISCOVER message
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    When the client sends a DHCPDECLINE for the offered address
    Then the administrative event log identifies the declined address
