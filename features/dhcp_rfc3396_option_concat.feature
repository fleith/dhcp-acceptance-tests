Feature: RFC 3396 Option concatenation and long options
  The server should accept requests that carry concatenated option fragments

  @ipv4_must_next @kea_rfc3396_request_reassembly_divergence
  Scenario: Server applies policy to a semantically reassembled request option
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER with concatenated host-name option fragments
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    And a DHCPACK finalizes the lease
    And the reassembled host name activates one matching server policy

  @kea @known_divergence @non_compliance
  Scenario: Kea exposes its fragmented host-name policy divergence
    Given the DHCP server is running
    When a client sends a DHCPDISCOVER with concatenated host-name option fragments
    Then the client receives a DHCPOFFER with a valid IP address in the subnet
    And a DHCPACK finalizes the lease
    And the reassembled host-name policy is absent

  @must_gap
  Scenario: Server splits and preserves a configured option longer than 255 octets
    Given the DHCP server is running
    When a client completes DORA requesting the oversized RFC 3396 option
    Then the offer and acknowledgement contain ordered RFC 3396 fragments
    And both responses reconstruct the configured oversized option exactly
