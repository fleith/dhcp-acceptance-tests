Feature: RFC 4702 Client FQDN Option (Option 81)
  The server should accept requests that carry the Client FQDN option
  and still complete the lease

  Scenario: Server still offers a lease when DISCOVER carries the Client FQDN option
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER with the Client FQDN option
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    And a DHCPACK finalizes the lease
