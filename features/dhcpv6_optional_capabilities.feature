@ipv6 @capability @requires_authenticated_reconfigure
Feature: Authenticated server-initiated DHCPv6 Reconfigure
  A service claiming authenticated Reconfigure must expose a test adapter that
  targets the current client while the suite independently validates RKAP.

  Scenario: Accepted client receives a valid authenticated Reconfigure
    Given a DHCPv6 client holds a Reconfigure-capable lease with an RKAP key
    When the service adapter triggers DHCPv6 Reconfigure for that client
    Then the client receives a valid unicast RKAP Reconfigure requesting RENEW
    And the client successfully renews the lease after Reconfigure

  @negative
  Scenario: Client without Reconfigure Accept is not targeted
    Given a DHCPv6 client holds a lease without accepting Reconfigure
    When the service adapter attempts Reconfigure for the non-accepting client
    Then no DHCPv6 Reconfigure targets the non-accepting client
    And the non-accepting client's lease remains renewable

  @negative
  Scenario: Tampering invalidates an authenticated Reconfigure
    Given a DHCPv6 client holds a Reconfigure-capable lease with an RKAP key
    When the service adapter triggers DHCPv6 Reconfigure for that client
    Then protected-field and digest tampering invalidate RKAP validation
    And no renewal is initiated for a rejected Reconfigure variant

  @negative
  Scenario: Replay values advance and a stale Reconfigure is rejected
    Given a DHCPv6 client holds a Reconfigure-capable lease with an RKAP key
    When the service sends two completed authenticated Reconfigure transactions
    Then the second Reconfigure has a greater replay-detection value
    And the previously accepted Reconfigure is rejected as a replay

  Scenario: Direct authenticated Reconfigure contains only permitted metadata
    Given a DHCPv6 client holds a Reconfigure-capable lease with an RKAP key
    When the service adapter triggers DHCPv6 Reconfigure for that client
    Then the direct Reconfigure contains only its required RFC 9915 options
    And the client lease remains renewable after Reconfigure metadata validation
