Feature: RFC 3442 Classless Static Route Option
  DHCPv4 clients should receive correctly encoded classless routes without
  conflicting legacy route options or destabilizing unusual requests.

  @ipv4_must_next
  Scenario: Server returns configured classless routes in OFFER and ACK
    Given the DHCP server is running
    When a client completes DORA requesting the Classless Static Route option
    Then the transaction-specific DHCPOFFER contains the configured classless routes
    And the transaction-specific DHCPACK contains the configured classless routes
    And both RFC 3442 responses contain a default route, a non-octet-prefix route, and multiple routes
    And both RFC 3442 responses split the oversized route option correctly

  @ipv4_should_next @kea_rfc3442_legacy_route_divergence
  Scenario: Classless routes suppress requested legacy route options
    Given the DHCP server is running
    When a client completes DORA requesting the Classless Static Route option
    Then both RFC 3442 responses omit legacy Router and Static Route options

  @ipv4 @kea @known_divergence @non_compliance @ipv4_should_next_divergence
  Scenario: Kea exposes its legacy Router option divergence
    Given the DHCP server is running
    When a client completes DORA requesting the Classless Static Route option
    Then at least one RFC 3442 response includes the known legacy Router option

  Scenario: Duplicate and unknown PRL codes do not prevent a valid exchange
    Given the DHCP server is running
    When a client sends DHCPDISCOVER with duplicated and unknown RFC 3442 PRL codes
    Then the server returns a transaction-specific DHCPOFFER for the unusual PRL
    When the client requests that offer with the same unusual PRL
    Then the server returns a transaction-specific DHCPACK for the offered address
