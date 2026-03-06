Feature: DHCPINFORM - configuration without address assignment (RFC 2131 §3.5)
  A client that already has an IP address may use DHCPINFORM to obtain
  configuration parameters without requesting a new lease

  Scenario: Client receives configuration options via DHCPINFORM
    Given a client holds a lease from the DHCP server
    When the client sends a DHCPINFORM to request configuration options
    Then the server responds with a DHCPACK containing configuration options
    And the DHCPACK does not assign a new IP address
