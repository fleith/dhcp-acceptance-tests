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
