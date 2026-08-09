@ipv6
Feature: DHCPv6 lease rebinding (RFC 8415)
  A client should be able to extend an active lease when rebinding to any
  available DHCPv6 server.

  Scenario: Client rebinds an active DHCPv6 lease
    Given a client holds a DHCPv6 lease from the server
    When the client sends a DHCPv6 REBIND message
    Then a matching DHCPv6 REPLY extends the same lease
