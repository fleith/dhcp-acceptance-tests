@ipv4 @kea @capability @requires_overlap_leases @overlap_lease_behavior
Feature: DHCPv4 lease behavior with overlapping subnets
  A server that accepts overlapping subnet configuration must select one scope
  consistently for a transaction.  The selected scope controls both the lease
  address and the options returned with it.

  Background:
    Given distinguishable overlapping DHCPv4 lease scopes are configured

  @overlap_direct
  Scenario: Direct client receives a consistent lease from the selected scope
    When a direct DHCPv4 client completes DORA in the overlapping topology
    Then the overlap DHCPOFFER and DHCPACK use the expected lease pool
    And both overlap responses carry the expected scope policy

  @negative @overlap_hint
  Scenario: Requested-address hint cannot move a client into the other scope
    When a direct DHCPv4 client requests an address from the non-selected overlapping pool
    Then the overlap DHCPOFFER and DHCPACK use the expected lease pool
    And the non-selected overlapping address is not allocated
    And both overlap responses carry the expected scope policy
