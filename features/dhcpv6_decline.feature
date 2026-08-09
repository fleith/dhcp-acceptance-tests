@ipv6
Feature: DHCPv6 declined address handling (RFC 8415)
  The server should acknowledge declined leases and quarantine suspect addresses.

  Scenario: Server does not advertise an address declined by an active client
    Given a client holds a DHCPv6 lease from the server
    When the client sends a DHCPv6 DECLINE for its active lease
    Then the server replies that the DHCPv6 DECLINE succeeded
    When a different client sends a DHCPv6 SOLICIT message
    Then the different client is advertised an address other than the declined address
