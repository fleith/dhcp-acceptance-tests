@ipv4 @capability
Feature: Optional DHCP service capabilities
  These scenarios run only when TEST_CAPABILITIES explicitly advertises the
  named capability and its adapter configuration is supplied.

  @requires_reload
  Scenario: A live configuration reload changes policy without losing leases
    Given a classed DHCPv4 binding exists before configuration reload
    When the service reload adapter applies updated class policy
    Then the pre-reload binding can still be renewed
    And a new classed client receives the reloaded policy

  @requires_ha
  Scenario: An HA peer preserves bindings during primary failure
    Given an active DHCPv4 binding exists before HA failover
    When the HA adapter isolates the active primary
    Then the binding can be rebound through the remaining HA peer
    And the remaining HA peer never allocates that active address to another client

  @requires_ddns
  Scenario: A committed FQDN lease creates its forward DNS record
    Given the DHCP service has a reachable authoritative DNS update target
    When a DHCPv4 client commits a lease with its configured FQDN
    Then the authoritative DNS service resolves the FQDN to the committed address

  @requires_multi_interface
  Scenario: A second directly connected interface selects its own subnet
    Given the test client has a configured second DHCPv4 interface
    When a DHCPv4 client acquires a lease through the second interface
    Then the second-interface lease belongs to its configured subnet

  @requires_storage_fault
  Scenario: A runtime lease-storage failure prevents an unrecorded commit
    Given an active DHCPv4 binding exists before a runtime storage failure
    When the storage-fault adapter makes lease persistence unavailable
    Then a new DHCPv4 client cannot commit an unrecorded lease
    When the storage-fault adapter restores lease persistence
    Then the pre-fault binding can still be renewed
