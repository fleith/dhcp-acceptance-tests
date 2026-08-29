@ipv6 @negative @malformed @bounded_fuzz @focused_robustness
Feature: Bounded DHCPv6 malformed-message robustness
  Every client-originated DHCPv6 message family must reject structurally
  truncated option metadata without changing an existing binding or poisoning
  the next valid transaction.

  Scenario: Every stateful DHCPv6 client message family rejects bounded wire mutations
    Given a client holds a DHCPv6 lease from the server
    When the client sends every stateful DHCPv6 message and wire-mutation pair
    Then the server discards every malformed DHCPv6 transaction
    When the client sends a DHCPv6 RENEW message
    Then the server responds with a DHCPv6 REPLY extending the lease

  @reference_malformed_dhcpv6_information_divergence
  Scenario: Stateless DHCPv6 rejects every bounded wire mutation
    Given a client holds a DHCPv6 lease from the server
    When DHCPv6 INFORMATION-REQUEST carries every bounded wire mutation
    Then the server discards every malformed DHCPv6 transaction
    When the client sends a DHCPv6 RENEW message
    Then the server responds with a DHCPv6 REPLY extending the lease

  @kea @known_divergence @non_compliance @malformed_dhcpv6_information_divergence
  Scenario: Kea processes malformed INFORMATION-REQUEST options
    Given a client holds a DHCPv6 lease from the server
    When DHCPv6 INFORMATION-REQUEST carries every bounded wire mutation
    Then the reference server exposes its malformed DHCPv6 INFORMATION-REQUEST behavior
    When the client sends a DHCPv6 RENEW message
    Then the server responds with a DHCPv6 REPLY extending the lease
