Feature: RFC 3011 Subnet Selection Option
  The server should accept packets that carry Subnet Selection option 118
  and honor alternate-subnet selection in the DHCPv4 test topology

  Scenario: Server still offers a lease when DISCOVER carries Subnet Selection option
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER with Subnet Selection option for the served subnet
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    And a DHCPACK finalizes the lease

  @kea
  Scenario: Server selects the alternate served subnet requested by Subnet Selection option
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER with Subnet Selection option for the alternate served subnet
    Then the client receives a DHCPOFFER with an IP address in the selected subnet
    And a DHCPACK finalizes the lease for the selected subnet
