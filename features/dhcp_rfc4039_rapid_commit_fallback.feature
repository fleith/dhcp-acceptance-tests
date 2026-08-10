@negative @capability @non_compliance
Feature: Unsupported RFC 4039 DHCPv4 Rapid Commit fallback safety
  The installed ISC DHCP and Kea backends do not implement DHCPv4 Rapid Commit.
  These capability and negative scenarios verify safe fallback behavior only and
  do not claim RFC 4039 implementation or count as RFC compliance coverage.

  Background:
    Given the DHCP server is running

  Scenario: A valid Rapid Commit request falls back to normal DORA
    When a client requests unsupported DHCPv4 Rapid Commit during discovery
    Then the server sends a normal DHCPOFFER without Option 80 or a rapid DHCPACK
    And the client completes the fallback with a normal DHCPREQUEST and DHCPACK without Option 80

  Scenario: A malformed Rapid Commit option does not poison the server
    When a client sends malformed nonzero-length DHCPv4 Rapid Commit
    And the same client completes a subsequent valid DORA
    Then the valid exchange succeeds after the malformed option
