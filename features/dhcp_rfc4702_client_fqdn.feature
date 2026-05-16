Feature: RFC 4702 Client FQDN Option (Option 81)
  The server should accept the Client FQDN option and echo it back in its
  reply, confirming the DNS update it will perform on the client's behalf

  Scenario: Server echoes the Client FQDN option in the DHCPACK
    Given the DHCP server is running
    When a client completes a DORA exchange carrying the Client FQDN option
    Then the server's DHCPACK echoes the Client FQDN option
