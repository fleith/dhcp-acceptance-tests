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

  @orchestrated @rfc9915_reserved_iid_pool @negative @reference_reserved_iid_pool_divergence
  Scenario: Allocator skips every registered reserved-IID range present in configured pools
    Given the DHCPv6 server is running
    When distinct clients exhaust the reserved-IID boundary pools
    Then every allocatable boundary address is committed exactly once
    And no reserved boundary IID is assigned

  @kea @orchestrated @known_divergence @non_compliance @rfc9915_reserved_iid_pool_divergence
  Scenario: Kea allocates reserved IIDs from explicitly configured pools
    Given the DHCPv6 server is running
    When distinct clients exhaust the reserved-IID boundary pools
    Then the reference allocator assigns a reserved boundary IID

  @rfc9915_address_generation @reference_predictable_iid_divergence
  Scenario: Default address allocation avoids a simple contiguous IID sequence
    Given the DHCPv6 server is running
    When several distinct clients request DHCPv6 addresses
    Then their generated IPv6 interface identifiers resist simple sequence predictors

  @kea @known_divergence @non_compliance @rfc9915_address_generation_divergence
  Scenario: Kea reference allocator exposes a simple contiguous IID sequence
    Given the DHCPv6 server is running
    When several distinct clients request DHCPv6 addresses
    Then their generated IPv6 interface identifiers form a contiguous sequence

  @requires_dhcpv6_rapid_commit @rfc9915_rebind_policy
  Scenario Outline: Rapid Commit policy creates every requested unknown REBIND resource
    Given the DHCPv6 server is running
    When an unknown client sends a DHCPv6 REBIND containing <resources>
    Then a matching DHCPv6 REPLY creates every requested binding
    And every created unknown REBIND resource renews successfully

    Examples:
      | resources       |
      | IA_NA           |
      | IA_PD           |
      | IA_NA and IA_PD |

  @orchestrated @rfc9915_rebind_disabled @negative @reference_disabled_rebind_policy_divergence
  Scenario Outline: Disabled binding creation returns per-IA NoBinding for unknown REBIND
    Given the DHCPv6 server is running
    When an unknown client sends a DHCPv6 REBIND containing <resources>
    Then every unknown IA reports NoBinding without assigning a resource

    Examples:
      | resources       |
      | IA_NA           |
      | IA_PD           |
      | IA_NA and IA_PD |

  @orchestrated @rfc9915_rebind_disabled @known_divergence @non_compliance
  Scenario: Reference servers omit NoBinding when Rapid Commit is disabled
    Given the DHCPv6 server is running
    When an unknown client sends a DHCPv6 REBIND containing IA_NA and IA_PD
    Then the reference unknown REBIND reply omits a required per-IA NoBinding status

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

  @negative @rfc9915_reply_closure
  Scenario: Interface-ID is absent across direct DHCPv6 lifecycle handlers
    Given a client holds a DHCPv6 lease from the server
    When the client sends a DHCPv6 RENEW message
    Then the server responds with a DHCPv6 REPLY extending the lease
    When the client sends a DHCPv6 REBIND message
    Then a matching DHCPv6 REPLY extends the same lease
    When the client sends a DHCPv6 CONFIRM for its active address
    Then the matching DHCPv6 CONFIRM reply reports Success
    When a client sends a DHCPv6 INFORMATION-REQUEST for DNS configuration
    Then the matching DHCPv6 REPLY contains DNS server "2001:4860:4860::8888" and domain "example.test"
    When the client sends a DHCPv6 RELEASE for its active lease
    Then the server returns a successful DHCPv6 RELEASE reply
    And every captured direct lifecycle response contains no Interface-ID
