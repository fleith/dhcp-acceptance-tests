Feature: RFC 3046 Relay Agent Information (Option 82)
  The server should handle packets containing relay-agent information
  in a predictable way in this direct-attach test topology

  Scenario: Server still offers a lease when DISCOVER carries Option 82
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER with Relay Agent Information option
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    And a DHCPACK finalizes the lease
