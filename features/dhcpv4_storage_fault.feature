@ipv4 @orchestrated @storage_fault
Feature: DHCPv4 runtime lease-storage failure and recovery
  A server must not lose a binding it acknowledged while storage was
  exhausted. After recovery, all durable bindings must retain ownership.

  @storage_fault_prepare
  Scenario: Record durable bindings before lease storage fails
    Given the isolated DHCPv4 storage-fault fixture is safely bounded
    When a durable DHCPv4 baseline batch is committed
    Then every pre-fault binding is unique and recorded

  @storage_fault_inject
  Scenario: The fault-time transaction is captured for reconciliation
    Given recorded durable DHCPv4 bindings and an active storage fault
    When a new DHCPv4 client attempts to commit during the storage fault
    Then the storage-fault transaction outcome is recorded for recovery verification

  @storage_fault_verify
  Scenario: Restored storage preserves ownership and accepts safe commits
    Given recorded DHCPv4 storage-fault transaction state
    When every pre-fault client reasserts its recorded binding
    Then every durable binding remains owned by its original client
    When the storage-fault client is reconciled after recovery
    Then its recovered state is consistent with the fault-time outcome
    And all storage-fault bindings are released and metrics are written
