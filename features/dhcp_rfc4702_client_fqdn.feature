Feature: RFC 4702 Client FQDN Option (Option 81)
  The server should accept the Client FQDN option and echo it back in its
  reply, confirming the DNS update it will perform on the client's behalf

  @ipv4_must_next
  Scenario Outline: DHCPACK preserves the Client FQDN encoding and E flag
    Given the DHCP server is running
    When a client completes a DORA exchange using <encoding> Client FQDN encoding
    Then the DHCPACK preserves <encoding> Client FQDN encoding

    Examples:
      | encoding |
      | DNS      |
      | ASCII    |
