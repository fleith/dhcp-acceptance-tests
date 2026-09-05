@ipv4 @capability @requires_option82_factory_namespaces @requires_factory_lifecycle @option82_factory_namespaces
Feature: Independent factory lease lifecycle
  A disposable target adapter exposes authoritative lease state so that a
  permissive ACK cannot conceal a lost or cross-factory binding.

  Background:
    Given three trusted factory relay scopes share one DHCPv4 client subnet
    And the disposable factory lifecycle fixture is reset
    When identical client identities commit the shared address in all factories
    Then all factory owners exist in authoritative lease state

  @negative
  Scenario: Release makes only Factory A available for reuse
    When Factory A releases its shared address
    Then Factory A alone has no active owner
    When a replacement client commits the shared address in Factory A
    Then all factory owners exist in authoritative lease state
    And every factory binding rebinds through its original relay scope

  @negative
  Scenario: Decline quarantines only Factory A
    When Factory A declines its shared address
    Then Factory A alone is quarantined
    And a contender cannot obtain Factory A's quarantined address
    And every factory binding rebinds through its original relay scope
    Then Factory A alone is quarantined

  @negative
  Scenario: An unscoped unicast renewal cannot choose between identical owners
    When an identical owner renews by unicast without factory metadata
    Then the ambiguous renewal receives no acknowledgement
    And authoritative factory leases remain unchanged
    And every factory binding rebinds through its original relay scope

  Scenario: Persistent restart preserves all duplicate-address owners
    When the factory adapter restarts the service preserving storage
    Then authoritative factory leases remain unchanged
    And every factory binding rebinds through its original relay scope
    And all factory owners exist in authoritative lease state
