Feature: RFC 6842 Client Identifier handling
  The server should treat client-identifier as the stable client identity

  Scenario: Same client-identifier with different chaddr gets same lease
    Given the DHCP server is running
    When a client with a client identifier acquires a lease
    And the same client identifier is used from a different hardware address
    Then the server offers the same IP address for that client identifier
