Feature: RFC 6842 Client Identifier handling
  The server should return a supplied client identifier unchanged and omit it
  when the client did not supply one.

  @must_gap @isc_rfc6842_divergence
  Scenario: Server returns the supplied client identifier unchanged
    Given the DHCP server is running
    When a client with a client identifier acquires a lease
    Then the offer and acknowledgement echo that client identifier unchanged

  @must_gap
  Scenario: Server omits client identifier when the client omits it
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER message
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    And a DHCPACK finalizes the lease
    Then the offer and acknowledgement omit the client identifier

  Scenario: Same client-identifier with different chaddr gets same lease
    Given the DHCP server is running
    When a client with a client identifier acquires a lease
    And the same client identifier is used from a different hardware address
    Then the server offers the same IP address for that client identifier
