Feature: DHCP lease renewal and expiry
  To maintain connectivity
  Clients must be able to renew their leases and handle expiry gracefully

  Scenario: Client renews an active lease
    Given a client holds a lease from the DHCP server
    When the lease reaches half of its lifetime
    And the client sends a DHCPREQUEST to renew
    Then the server responds with a DHCPACK extending the lease

  Scenario: Lease expires when not renewed
    Given a client holds a lease from the DHCP server
    When the lease time elapses without renewal
    Then the server reclaims the IP address for reassignment

  Scenario: Client rebinds successfully without specifying server identifier
    Given a client holds a lease from the DHCP server
    When the client enters REBINDING state
    And the client sends a broadcast DHCPREQUEST to rebind
    Then the server responds with a DHCPACK extending the lease

  Scenario: Client falls back to rebinding after a misdirected renewal attempt
    Given a client holds a lease from the DHCP server
    When the client sends a DHCPREQUEST renewal attempt to an unreachable server
    And the client enters REBINDING state
    And the client sends a broadcast DHCPREQUEST to rebind
    Then the server responds with a DHCPACK extending the lease
