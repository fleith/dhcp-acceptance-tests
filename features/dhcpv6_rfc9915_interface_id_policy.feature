@ipv6 @kea @capability @requires_dhcpv6_interface_id_policy @rfc9915_interface_id_policy
Feature: Opaque DHCPv6 Interface-ID assignment policy (RFC 9915)
  A server configured to use relay Interface-ID for assignment policy should
  compare the complete opaque value and use the relay closest to the client.

  Scenario Outline: Exact opaque Interface-ID selects only its configured pool
    Given the DHCPv6 server is running
    When a relay uses configured opaque Interface-ID "<interface_id>"
    Then the relayed ADVERTISE assigns an address from policy pool "<pool>"
    And the RELAY-REPLY preserves configured Interface-ID "<interface_id>" byte for byte
    When the relay commits the Interface-ID policy offer
    Then the relayed REPLY commits the same address in policy pool "<pool>"

    Examples:
      | interface_id | pool |
      | A            | A    |
      | B            | B    |

  @negative
  Scenario: Near-match and split duplicate Interface-IDs cannot activate policy
    Given the DHCPv6 server is running
    When relays use near-match and split-duplicate variants of configured Interface-ID "A"
    Then none of the Interface-ID variants receives an address from either policy pool
    When a relay uses configured opaque Interface-ID "A"
    Then the relayed ADVERTISE assigns an address from policy pool "A"

  Scenario Outline: Closest-client Interface-ID controls nested relay policy
    Given the DHCPv6 server is running
    When nested relays use closest-client Interface-ID "<inner>" and outer Interface-ID "<outer>"
    Then the relayed ADVERTISE assigns an address from policy pool "<pool>"
    And both nested RELAY-REPLY layers preserve Interface-IDs "<inner>" and "<outer>"
    When the relay commits the Interface-ID policy offer
    Then the relayed REPLY commits the same address in policy pool "<pool>"

    Examples:
      | inner | outer | pool |
      | A     | B     | A    |
      | B     | A     | B    |
