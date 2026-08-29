@ipv4 @orchestrated @capacity @large_pool
Feature: DHCPv4 large-pool capacity and endurance
  A DHCP server must preserve lease ownership and useful response performance
  when a substantially larger isolated pool is filled or churned over time.

  @capacity_scale
  Scenario: Concurrent waves fill exhaust and safely recycle a large pool
    Given the isolated DHCPv4 capacity profile is safely bounded
    When concurrent waves fill the configured DHCPv4 capacity pool
    Then every large-pool binding is unique and within the configured pool
    When every large-pool binding is renewed by its original client
    Then every large-pool renewal preserves its binding
    When one additional client discovers against the full capacity pool
    Then the full capacity pool returns no offer
    When a configured capacity subset is released and replaced concurrently
    Then only released capacity addresses are reassigned without conflicts
    And large-pool response latency and throughput meet configured limits
    And the DHCPv4 capacity state is recorded

  @capacity_endurance
  Scenario: Duration-based lease churn remains correct and responsive
    Given the isolated DHCPv4 capacity profile is safely bounded
    When DHCPv4 capacity batches churn for the configured duration
    Then every endurance transaction is unique and the minimum volume completes
    And released capacity addresses are reused during endurance
    And large-pool response latency and throughput meet configured limits
    And the DHCPv4 capacity state is recorded

  @capacity_verify
  Scenario: Capacity resource scaling remains bounded and service recovers
    Given recorded DHCPv4 capacity state and server resource samples
    Then DHCPv4 capacity memory and process scaling meet configured limits
    When all recorded DHCPv4 capacity bindings are released
    Then a fresh DHCPv4 batch succeeds after the capacity run
    And the DHCPv4 capacity metrics report is written
