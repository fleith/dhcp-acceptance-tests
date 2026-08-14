@ipv4 @capability @requires_server_ping_check @rfc2131 @server_ping_check
Feature: RFC 2131 server-side candidate address probing
  A configured DHCPv4 server probes a candidate address before DHCPOFFER so
  that an address already answering ICMP is not assigned to another client.
  These scenarios use a one-address pool and run in separate fresh fixtures.

  @ping_check_silent
  Scenario: A silent candidate address is offered after the ICMP probe
    Given the ping-check fixture contains exactly one candidate address
    And no host owns the ping-check candidate address
    When a DHCPv4 client discovers a lease in the ping-check fixture
    Then the server sends an ICMP Echo Request for the candidate address
    And the silent candidate address is offered after the probe

  @negative @ping_check_occupied
  Scenario: A responding candidate address is withheld
    Given the ping-check fixture contains exactly one candidate address
    And the test peer owns and answers for the ping-check candidate address
    When a DHCPv4 client discovers a lease in the ping-check fixture
    Then the server sends an ICMP Echo Request for the candidate address
    And the test peer returns an ICMP Echo Reply for the candidate address
    And the responding candidate address is not offered
