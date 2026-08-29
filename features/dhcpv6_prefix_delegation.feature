@ipv6
Feature: DHCPv6 Prefix Delegation (RFC 9915)
  A requesting router should obtain, maintain, and safely release delegated
  IPv6 prefixes while the server protects existing bindings.

  Background:
    Given the DHCPv6 server is ready for prefix delegation

  Scenario: Client obtains a delegated prefix without a hint
    When the client solicits a delegated prefix without a hint
    Then the server advertises a delegated prefix
    And the advertised prefix matches the configured delegation policy
    When the client requests the advertised delegated prefix
    Then the server replies with the delegated prefix binding

  @policy
  Scenario: Server accepts a matching configured prefix-length hint
    When the client solicits a delegated prefix with the configured length hint
    Then the server advertises the configured prefix length for the matching hint
    When the client requests the advertised delegated prefix
    Then the server replies with the delegated prefix binding

  Scenario: Client renews a delegated prefix
    Given the client holds an active delegated prefix
    When the client renews the delegated prefix
    Then the server renews the same delegated prefix

  Scenario: Client rebinds a delegated prefix
    Given the client holds an active delegated prefix
    When the client rebinds the delegated prefix
    Then an available server rebinds the same delegated prefix

  Scenario: Address and prefix leases are returned together
    When the client requests an IA_NA and an IA_PD together
    Then the server returns both address and prefix bindings
    And their applicable T1 and T2 timers are consistent

  @rfc9915_reply_closure
  Scenario: Combined address and prefix renewal preserves identifiers and timers
    When the client requests an IA_NA and an IA_PD together
    Then the server returns both address and prefix bindings
    When the client renews the combined address and prefix binding
    Then the combined RENEW reply preserves identifiers and equal IA timers

  Scenario: Multiple IA_PD options have independent identities
    When the client requests two delegated prefixes with unique IAIDs
    Then the server returns two unique delegated prefixes for those IAIDs

  Scenario: Server ignores client-supplied IA_PD timers
    When the client solicits a delegated prefix with nonzero T1 and T2
    Then the server replaces the client-supplied IA_PD timers

  @negative
  Scenario: Out-of-pool prefix hint is never granted
    When the client solicits the configured out-of-pool prefix hint
    Then the server does not grant the out-of-pool prefix

  @negative
  Scenario: Forged RELEASE cannot remove another client's binding
    Given the client holds an active delegated prefix
    When a different DUID sends a RELEASE for the delegated prefix
    Then the server reports no binding or preserves the original binding

  @policy
  Scenario: Released delegated prefix is deterministically reusable
    Given the client holds an active delegated prefix
    And every other configured delegated prefix is bound
    When the client releases the delegated prefix
    Then the server accepts the delegated prefix release
    When a different DUID requests the released delegated prefix
    Then the server delegates exactly the released prefix

  @negative
  Scenario: Exhausted prefix pool returns NoPrefixAvail
    Given every configured delegated prefix is bound
    When an additional client solicits a delegated prefix
    Then the advertised IA_PD contains NoPrefixAvail and no prefix

  @negative @rfc9915_rebind_ownership
  Scenario: Address-only REBIND excludes another client's IA_NA
    Given two DHCPv6 clients each hold an address and delegated prefix
    When one client sends an "address-only" mixed-ownership REBIND
    Then the "address-only" REBIND reply preserves owned resources and never activates forged resources
    And every positive mixed REBIND resource is renewable by the attacker
    And both original clients can renew their address and prefix bindings

  @negative @rfc9915_rebind_ownership
  Scenario: Prefix-only REBIND excludes another client's IA_PD
    Given two DHCPv6 clients each hold an address and delegated prefix
    When one client sends a "prefix-only" mixed-ownership REBIND
    Then the "prefix-only" REBIND reply preserves owned resources and never activates forged resources
    And every positive mixed REBIND resource is renewable by the attacker
    And both original clients can renew their address and prefix bindings

  @negative @rfc9915_rebind_ownership
  Scenario Outline: Cross-type REBIND excludes another client's resource
    Given two DHCPv6 clients each hold an address and delegated prefix
    When one client sends a "<shape>" mixed-ownership REBIND
    Then the "<shape>" REBIND reply preserves owned resources and never activates forged resources
    And every positive mixed REBIND resource is renewable by the attacker
    And both original clients can renew their address and prefix bindings

    Examples:
      | shape                      |
      | address-with-forged-prefix |
      | prefix-with-forged-address |

  @negative @rfc9915_rebind_ownership
  Scenario: Fully mixed REBIND excludes another client's IA_NA and IA_PD
    Given two DHCPv6 clients each hold an address and delegated prefix
    When one client sends a "fully-mixed" mixed-ownership REBIND
    Then the "fully-mixed" REBIND reply preserves owned resources and never activates forged resources
    And every positive mixed REBIND resource is renewable by the attacker
    And both original clients can renew their address and prefix bindings
