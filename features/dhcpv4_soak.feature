@ipv4 @orchestrated @soak
Feature: DHCPv4 bounded soak and resource stability
  Repeated lease churn must preserve allocation correctness and pool reuse
  while response latency and server resource use remain within explicit limits.

  @soak_run
  Scenario: Sustained lease churn remains correct over time
    Given the isolated DHCPv4 soak profile is safely bounded
    When repeated DHCPv4 soak batches acquire and release leases
    Then every DHCPv4 soak transaction completes without active duplication
    And released DHCPv4 pool addresses are reused without conflicts
    And DHCPv4 response latency remains stable through the soak

  @soak_verify
  Scenario: The server remains available with bounded resource growth
    Given completed DHCPv4 soak state and server resource samples
    Then DHCPv4 server memory and process growth remain within configured limits
    And a fresh DHCPv4 batch succeeds after the soak
    And the DHCPv4 soak metrics report is written
