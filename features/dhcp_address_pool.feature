Feature: DHCP address pool behaviour (RFC 2131 §4.1)
  The server should maintain stable address bindings for known clients

  Scenario: Client reconnects and receives a reusable address from the pool
    Given a client holds a lease from the DHCP server
    When the client sends a DHCPRELEASE message
    Then the server marks the IP address as available again
    When a client sends a DHCPDISCOVER message
    Then the client receives a DHCPOFFER with a reusable IP address from the pool
    And a DHCPACK finalizes the lease
