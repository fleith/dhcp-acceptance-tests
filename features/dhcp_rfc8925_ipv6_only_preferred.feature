@rfc8925
Feature: RFC 8925 IPv6-Only Preferred option delivery
  DHCPv4 servers should deliver the configured IPv6-Only Preferred wait timer
  only to clients and subnets configured to receive option 108. DORA completion
  is a deliberate fallback path, not normal IPv6-mostly client behavior.

  @ipv4_partial_next
  Scenario: Server returns option 108 using an addressless offer or IPv4 fallback
    Given the DHCP server is running
    When an RFC 8925 client requests option 108 and follows any addressful fallback
    Then its matching DHCPOFFER contains the configured IPv6-Only Preferred wait
    And any fallback DHCPACK contains the configured IPv6-Only Preferred wait
    And all IPv6-Only Preferred responses use one RFC-compliant four-byte timer

  Scenario: Duplicate option 108 PRL entries remain stable
    Given the DHCP server is running
    When an RFC 8925 client requests duplicate option 108 PRL entries
    Then all matching responses contain the same configured IPv6-Only Preferred wait

  @ipv4_must_next @rfc8925_zero_default @requires_rfc8925_zero_default
  Scenario: An IPv6-mostly pool without a wait override returns zero
    Given the DHCP server is running
    When an RFC 8925 client requests option 108 and follows any addressful fallback
    Then all matching responses contain a four-octet zero wait

  Scenario: An ordinary client completes DORA without option 108
    Given the DHCP server is running
    When an ordinary RFC 8925 client completes DORA without requesting option 108
    Then both matching responses omit the IPv6-Only Preferred option
    And the ordinary RFC 8925 exchange completes with one leased address

  @relay @ipv4_partial_next
  Scenario: A relayed non-IPv6-mostly subnet omits option 108
    Given the DHCP server is running
    When an RFC 8925 client requests option 108 on the relayed non-IPv6-mostly subnet
    Then both matching relayed-subnet responses omit the IPv6-Only Preferred option
