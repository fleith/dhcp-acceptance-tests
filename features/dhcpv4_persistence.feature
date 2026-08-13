@ipv4 @orchestrated @persistence
Feature: DHCPv4 persistent binding recovery
  These phases are executed by run_lifecycle_tests.sh around graceful and
  abrupt server restarts. They are excluded from ordinary single-process runs.

  @persistence_prepare
  Scenario: Persist an active binding before server interruption
    Given the DHCP server is running
    When the persistent DHCPv4 client acquires and records a lease
    Then the persistent lease state file identifies an active binding

  @persistence_verify
  Scenario: Recover the recorded binding after server interruption
    Given a recorded persistent DHCPv4 binding
    When a different client requests the recorded address
    Then the different client is not offered the active recorded address
    When the persistent client enters INIT-REBOOT for the recorded address
    Then the server acknowledges the recorded persistent binding

  @persistence_cleanup
  Scenario: Release the recorded persistent binding
    Given a recorded persistent DHCPv4 binding
    When the persistent client releases the recorded binding
    Then the persistent lease state file is removed
