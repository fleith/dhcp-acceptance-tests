@ipv6
Feature: DHCPv6 Client FQDN negotiation (RFC 4704)
  The server should negotiate DNS update responsibility only when a client
  supplies and requests the DHCPv6 Client FQDN option.

  @kea
  Scenario: Client negotiates its FQDN while acquiring a lease
    Given the DHCPv6 server is running
    When an RFC 4704 client sends a SOLICIT with its configured FQDN and requests option 39
    Then the matching ADVERTISE contains the negotiated RFC 4704 FQDN
    When the RFC 4704 client sends a REQUEST with its configured FQDN and requests option 39
    Then the matching REPLY contains the negotiated RFC 4704 FQDN

  @kea
  Scenario: Server handles a partial client name
    Given the DHCPv6 server is running
    When an RFC 4704 client sends a SOLICIT with a partial FQDN and requests option 39
    Then the matching ADVERTISE contains a valid RFC 4704 name for the partial FQDN

  @isc
  Scenario: Server omits an unrequested Client FQDN option
    Given the DHCPv6 server is running
    When an RFC 4704 client sends a SOLICIT with its FQDN but omits option 39 from the ORO
    Then the matching ADVERTISE does not contain an RFC 4704 Client FQDN option

  @kea @non_compliance @known_divergence
  Scenario: Kea 2.2 documents its unrequested Client FQDN behavior
    Given the DHCPv6 server is running
    When an RFC 4704 client sends a SOLICIT with its FQDN but omits option 39 from the ORO
    Then the matching ADVERTISE exposes the known Kea 2.2 unrequested FQDN behavior

  Scenario: Server does not invent a Client FQDN option
    Given the DHCPv6 server is running
    When an RFC 4704 client requests option 39 without sending a Client FQDN option
    Then the matching ADVERTISE does not contain an RFC 4704 Client FQDN option

  @kea
  Scenario: Server negotiates DNS update responsibility using legal flags
    Given the DHCPv6 server is running
    When an RFC 4704 client sends a SOLICIT with a legal S preference
    Then the matching ADVERTISE negotiates RFC 4704 flags according to server policy

  @kea @negative
  Scenario: Server remains responsive after a truncated DNS label
    Given the DHCPv6 server is running
    When an RFC 4704 client sends a SOLICIT with a truncated FQDN DNS label
    Then the malformed FQDN transaction does not receive a committed lease
    When the client sends a valid RFC 4704 SOLICIT after the malformed FQDN
    Then the matching ADVERTISE proves RFC 4704 negotiation remains responsive
