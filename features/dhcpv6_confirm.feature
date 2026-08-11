@ipv6 @rfc9915_extended
Feature: DHCPv6 address confirmation (RFC 9915)
  A client that may have changed links should be able to confirm whether its
  existing address is still appropriate without renewing the lease.

  Scenario: Server confirms an address that remains on-link
    Given a client holds a DHCPv6 lease from the server
    When the client sends a DHCPv6 CONFIRM for its active address
    Then the matching DHCPv6 CONFIRM reply reports Success

  @negative
  Scenario: Server rejects an address from another link
    Given a client holds a DHCPv6 lease from the server
    When the client sends a DHCPv6 CONFIRM for an off-link address
    Then the matching DHCPv6 CONFIRM reply reports NotOnLink

  @negative
  Scenario: Malformed CONFIRM messages are ignored without poisoning the server
    Given a client holds a DHCPv6 lease from the server
    When the client sends a DHCPv6 CONFIRM without a Client Identifier
    Then the server does not answer the malformed DHCPv6 CONFIRM
    When the client sends a DHCPv6 CONFIRM containing a Server Identifier
    Then the server does not answer the malformed DHCPv6 CONFIRM
    When the client sends a DHCPv6 CONFIRM for its active address
    Then the matching DHCPv6 CONFIRM reply reports Success
