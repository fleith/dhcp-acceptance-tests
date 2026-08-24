@ipv6
Feature: DHCPv6 stateless configuration (RFC 9915)
  The server should provide requested configuration without assigning an address.

  @rfc9915_reply_closure
  Scenario: Client requests DNS configuration
    Given the DHCPv6 server is running
    When a client sends a DHCPv6 SOLICIT message
    Then the client receives a DHCPv6 ADVERTISE from the server
    When a client sends a DHCPv6 INFORMATION-REQUEST for DNS configuration
    Then the matching DHCPv6 REPLY contains DNS server "2001:4860:4860::8888" and domain "example.test"
    And the INFORMATION-REQUEST REPLY uses the learned server DUID
