Feature: RFC 3011 Subnet Selection Option
  The server should accept packets that carry Subnet Selection option 118
  and honor alternate-subnet selection in the DHCPv4 test topology

  Scenario: Server still offers a lease when DISCOVER carries Subnet Selection option
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER with Subnet Selection option for the served subnet
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    And a DHCPACK finalizes the lease

  @negative @must_gap @kea_rfc3011_default_divergence
  Scenario: Subnet Selection support is disabled by default
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER with Subnet Selection option for the alternate served subnet
    Then default-disabled Subnet Selection is ignored without an echo

  @ipv4_wire @ipv4_partial_next @isc_rfc3011_selection_divergence
  Scenario: Server selects the alternate served subnet requested by Subnet Selection option
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER selecting the alternate subnet with a conflicting address hint
    Then the client receives a DHCPOFFER with an IP address in the selected subnet
    And a DHCPACK finalizes the lease for the selected subnet
    And no selected-subnet response contains an address outside that subnet
    And both selected-subnet responses echo Subnet Selection unchanged
