Feature: DHCP INIT-REBOOT state (RFC 2131 §3.2)
  When a client reboots with a previously assigned address
  it skips the DISCOVER phase and directly requests its old address

  Scenario: Server confirms a valid previous address when client reboots
    Given a client holds a lease from the DHCP server
    When the client reboots and sends a DHCPREQUEST for its previous address
    Then the server responds with a DHCPACK confirming the address

  Scenario: Server sends DHCPNAK when rebooted client requests address outside the server's subnet
    Given a client holds a lease from the DHCP server
    When the client reboots and sends a DHCPREQUEST for an address outside the server's subnet
    Then the server responds with a DHCPNAK
