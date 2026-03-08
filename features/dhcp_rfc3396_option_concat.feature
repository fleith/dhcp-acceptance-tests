Feature: RFC 3396 Option concatenation and long options
  The server should accept requests that carry concatenated option fragments

  Scenario: Server accepts a DHCPDISCOVER with concatenated host-name fragments
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER with concatenated host-name option fragments
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    And a DHCPACK finalizes the lease
