@ipv6 @capability @requires_dhcpv6_request_observability @rfc9915_request_regeneration
Feature: Observable DHCPv6 REQUEST response regeneration
  A target that exposes a REQUEST-processing counter can prove that an
  identical retransmission is processed again rather than served from a cache.

  Scenario: An identical REQUEST is regenerated exactly once
    Given a client holds a DHCPv6 lease from the server
    And the service REQUEST-processing counter is recorded
    When the client retransmits the identical DHCPv6 REQUEST
    Then the retransmitted REQUEST returns the same binding and identifiers
    And the service REQUEST-processing counter advances by one
