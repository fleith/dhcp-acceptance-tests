Feature: RFC 3442 Classless Static Route Option
  DHCPv4 clients should receive correctly encoded classless routes alongside any
  legacy route options without destabilizing unusual requests.

  Scenario: Server returns configured classless routes in OFFER and ACK
    Given the DHCP server is running
    When a client completes DORA requesting the Classless Static Route option
    Then the transaction-specific DHCPOFFER contains the configured classless routes
    And the transaction-specific DHCPACK contains the configured classless routes
    And both RFC 3442 responses contain a default route, a non-octet-prefix route, and multiple routes
    And the configured classless default route is distinct from any legacy Router option

  Scenario: Duplicate and unknown PRL codes do not prevent a valid exchange
    Given the DHCP server is running
    When a client sends DHCPDISCOVER with duplicated and unknown RFC 3442 PRL codes
    Then the server returns a transaction-specific DHCPOFFER for the unusual PRL
    When the client requests that offer with the same unusual PRL
    Then the server returns a transaction-specific DHCPACK for the offered address
