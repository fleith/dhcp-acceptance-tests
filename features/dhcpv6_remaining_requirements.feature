@ipv6 @rfc9915_remaining
Feature: Remaining DHCPv6 server requirements from RFC 9915
  Representative boundary cases cover address generation, configured rebinding,
  server selection preference, and the scope of relay-only metadata.

  @negative
  Scenario: Reserved IPv6 interface identifiers are never offered
    Given the DHCPv6 server is running
    When representative reserved IPv6 interface identifiers are requested by distinct clients
    Then no DHCPv6 response offers a reserved IPv6 interface identifier
    When a client sends a DHCPv6 SOLICIT message
    Then the client receives a DHCPv6 ADVERTISE from the server

  @rfc9915_address_generation @reference_predictable_iid_divergence
  Scenario: Default address allocation avoids a simple contiguous IID sequence
    Given the DHCPv6 server is running
    When several distinct clients request DHCPv6 addresses
    Then their generated IPv6 interface identifiers are not a contiguous sequence

  @kea @known_divergence @non_compliance @rfc9915_address_generation_divergence
  Scenario: Kea reference allocator exposes a simple contiguous IID sequence
    Given the DHCPv6 server is running
    When several distinct clients request DHCPv6 addresses
    Then their generated IPv6 interface identifiers form a contiguous sequence

  @requires_dhcpv6_rapid_commit
  Scenario: Configured server creates an unknown binding during REBIND
    Given the DHCPv6 server is running
    When an unknown client sends a DHCPv6 REBIND with an on-link address hint
    Then a matching DHCPv6 REPLY creates a renewable binding
    When the client sends a DHCPv6 RENEW message
    Then the server responds with a DHCPv6 REPLY extending the lease

  @rfc9915_preference
  Scenario: DHCPv6 server advertises the configured effective preference
    Given the DHCPv6 server is running
    And the client requests the DHCPv6 Preference option
    When a client sends a DHCPv6 SOLICIT message
    Then the client receives a DHCPv6 ADVERTISE from the server
    And the ADVERTISE has the configured effective server preference

  @negative
  Scenario: Interface-ID is absent from direct DHCPv6 server messages
    Given the DHCPv6 server is running
    When a client sends a DHCPv6 SOLICIT message
    Then the client receives a DHCPv6 ADVERTISE from the server
    When the client sends a DHCPv6 REQUEST message
    Then the server responds with a DHCPv6 REPLY that finalizes the lease
    And the direct ADVERTISE and REPLY contain no Interface-ID

  @negative
  Scenario: Direct client Interface-ID cannot escape into a server response
    Given the DHCPv6 server is running
    When a direct client sends a SOLICIT containing an illegal Interface-ID
    Then no direct server response contains Interface-ID
    When a client sends a DHCPv6 SOLICIT message
    Then the client receives a DHCPv6 ADVERTISE from the server
