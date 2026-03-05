Feature: DHCP lease assignment and release
  As a network administrator
  I want to verify that the DHCP server assigns and releases IP addresses correctly
  So that clients always receive valid addresses from the configured subnet

  Scenario: Client obtains a new DHCP lease
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER message
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    And a DHCPACK finalizes the lease

  Scenario: Client releases a DHCP lease
    Given a client holds a lease from the DHCP server
    When the client sends a DHCPRELEASE message
    Then the server marks the IP address as available again
