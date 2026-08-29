@ipv6 @capability @requires_dhcpv6_generation_lifecycle @requires_dhcpv6_rapid_commit @rfc9915_generation_lifecycle
Feature: DHCPv6 address generation across subnets and restarts
  A bounded two-subnet topology makes collision protection and reuse observable
  before and after repeated persistent service restarts.

  Scenario: Generated addresses remain unique and reusable across persistent restarts
    Given the DHCPv6 generation lifecycle topology is configured
    When a large client sample commits addresses in both configured subnets
    Then every generated address is unique and belongs to its selected subnet
    And allocation-order IID samples resist simple predictors in both subnets
    When the service adapter performs two persistent DHCPv6 restarts
    Then every recorded owner rebinds its exact address after each restart
    When fresh clients fill the remaining capacity in both subnets
    Then no fresh allocation collides with a recorded active address
    And post-restart allocation fingerprints do not repeat earlier samples
    When half of the original bindings are released in each subnet
    Then replacement clients reuse only released addresses without duplicates
