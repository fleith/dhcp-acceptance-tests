Feature: DHCP INIT-REBOOT state (RFC 2131 §3.2)
  When a client reboots with a previously assigned address
  it skips the DISCOVER phase and directly requests its old address

  Scenario: Server confirms a valid previous address when client reboots
    Given a client holds a lease from the DHCP server
    When the client reboots and sends a DHCPREQUEST for its previous address
    Then the server responds with a DHCPACK confirming the address

  @negative
  Scenario: Server sends DHCPNAK when rebooted client requests address outside the server's subnet
    Given a client holds a lease from the DHCP server
    When the client reboots and sends a DHCPREQUEST for an address outside the server's subnet
    Then the server responds with a DHCPNAK

  @negative @must_gap @reference_init_reboot_divergence
  Scenario: Unknown client receives no answer for a same-subnet INIT-REBOOT address
    Given the DHCP server is running
    When an unknown client sends INIT-REBOOT for an unused same-subnet pool address
    Then the unknown INIT-REBOOT transaction receives no DHCPACK or DHCPNAK
