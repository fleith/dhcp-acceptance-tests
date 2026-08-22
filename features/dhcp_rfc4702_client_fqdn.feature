Feature: RFC 4702 Client FQDN Option (Option 81)
  The server should accept the Client FQDN option and echo it back in its
  reply, confirming the DNS update it will perform on the client's behalf

  @ipv4_must_next @ipv4_partial_next
  Scenario Outline: DHCPACK preserves the Client FQDN encoding and E flag
    Given the DHCP server is running
    When a client completes a DORA exchange using <encoding> Client FQDN encoding
    Then the DHCPACK preserves <encoding> Client FQDN encoding

    Examples:
      | encoding |
      | DNS      |
      | ASCII    |

  @ipv4_partial_next
  Scenario: Server completes a partial Client FQDN with its configured suffix
    Given the DHCP server is running
    When a client completes DORA with a partial DNS Client FQDN
    Then the DHCPACK Client FQDN contains the configured complete name

  @negative @ipv4_partial_next
  Scenario: Client FQDN takes precedence over a conflicting Host Name
    Given the DHCP server is running
    When a client completes DORA with conflicting Client FQDN and Host Name options
    Then the DHCPACK Client FQDN uses the Option 81 name

  @negative @ipv4_should_next @requires_rfc4702_ascii_unsupported
  Scenario: Unsupported ASCII Client FQDN encoding is ignored
    Given the DHCP server is running
    When a client completes DORA with an unsupported ASCII Client FQDN option
    Then neither response contains a Client FQDN option

  @ipv4_partial_next @kea_rfc4702_rcode_divergence
  Scenario Outline: Server-sent Client FQDN options use the deprecated RCODE values
    Given the DHCP server is running
    When a client completes a DORA exchange using <encoding> Client FQDN encoding
    Then every returned Client FQDN option sets RCODE1 and RCODE2 to 255

    Examples:
      | encoding |
      | DNS      |
      | ASCII    |
