Feature: DHCP lease options validation (RFC 2131 §4.3.1, §4.4.5)
  The DHCP server must include required network options and correct timer
  values in its DHCPACK responses

  @ipv4_wire
  Scenario: DHCPACK includes required network configuration options
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER message
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    And a DHCPACK finalizes the lease
    Then the DHCPACK includes a subnet mask option
    And the DHCPACK includes a router option
    And the DHCPACK includes a domain name server option
    And the DHCPACK places the subnet mask before the router option
    And the DHCPACK encodes both DNS servers in a valid address list

  @ipv4_wire
  Scenario: DHCPACK includes correct T1 and T2 lease timer values
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER message
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    And a DHCPACK finalizes the lease
    Then the DHCPACK T1 timer is approximately half the lease time
    And the DHCPACK T2 timer is approximately 87.5% of the lease time
    And the DHCPACK encodes lease time as exactly four octets
