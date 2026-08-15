@ipv4 @orchestrated @stress_crash
Feature: DHCPv4 mixed load and crash consistency
  A DHCP server under sustained allocation, renewal, and retransmission load
  must never duplicate an active address.  Every binding acknowledged before
  an abrupt process death must remain owned by the same client after restart.

  @stress_prepare
  Scenario: Sustained churn leaves a unique durable active batch
    Given the isolated DHCPv4 stress fixture is safely bounded
    When sustained DHCPv4 churn runs before a committed stress batch
    Then every pre-crash stress binding is unique and recorded
    And each completed stress batch meets its latency deadline

  @stress_inflight
  Scenario: Mixed client traffic remains safe while the server crashes
    Given recorded pre-crash DHCPv4 stress bindings
    When mixed allocation renewal and retransmission traffic runs until the server crashes
    Then every acknowledged in-flight binding is recorded without duplication
    And the orchestrated DHCPv4 server crash was observed

  @stress_verify
  Scenario: A restarted server recovers all acknowledged stress bindings
    Given recorded acknowledged DHCPv4 stress bindings
    When all recorded stress clients reassert their bindings after restart
    Then every recorded stress binding is acknowledged for its original client
    When a fresh DHCPv4 batch acquires leases after crash recovery
    Then no post-crash lease duplicates an active recorded binding
    And the DHCPv4 stress metrics satisfy the configured limits

  @stress_cleanup
  Scenario: Stress bindings are released after recovery verification
    Given recorded acknowledged DHCPv4 stress bindings
    When all DHCPv4 stress bindings are released
    Then the DHCPv4 stress coordination state is removed
