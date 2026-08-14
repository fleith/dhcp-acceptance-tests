@ipv6 @capability @requires_authenticated_reconfigure
Feature: Authenticated server-initiated DHCPv6 Reconfigure
  A service claiming authenticated Reconfigure must expose a test adapter that
  triggers a server-originated message for a Reconfigure-Accept client.

  Scenario: An authenticated Reconfigure causes the bound client to renew
    Given a DHCPv6 client holds a Reconfigure-capable lease
    When the service adapter triggers DHCPv6 Reconfigure for that client
    Then the client receives a server-authenticated Reconfigure requesting RENEW
    And the client successfully renews the lease after Reconfigure
