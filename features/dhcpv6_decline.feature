@ipv6
Feature: DHCPv6 declined address handling (RFC 9915)
  The server should acknowledge declined leases and quarantine suspect addresses.

  @negative @rfc9915_reply_closure
  Scenario: Server does not advertise an address declined by an active client
    Given a client holds a DHCPv6 lease from the server
    When the client sends a DHCPv6 DECLINE for its active lease
    Then the server replies that the DHCPv6 DECLINE succeeded
    And the direct DECLINE reply contains no Interface-ID
    When the client sends another DHCPv6 SOLICIT after declining the lease
    Then the client is advertised an address other than the declined address
