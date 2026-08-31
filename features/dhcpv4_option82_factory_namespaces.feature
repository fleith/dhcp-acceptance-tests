@ipv4 @capability @requires_option82_factory_namespaces @option82_factory_namespaces @rfc3046
Feature: Option 82 scoped factory address spaces
  A target service may deliberately extend RFC 3046 policy so that a trusted
  relay identity and opaque Circuit ID select an independent lease namespace.
  The target fixture gives every factory the same single-address pool, proving
  that duplicate address bytes represent separate active bindings.

  Background:
    Given three trusted factory relay scopes share one DHCPv4 client subnet

  Scenario: Three factories commit and rebind the same IPv4 address independently
    When one client in each factory completes DORA through its trusted relay
    Then every factory commits the configured shared IPv4 address
    And every factory response preserves its own giaddr and Option 82 bytes
    And every factory binding rebinds through its original relay scope

  @negative
  Scenario: A Circuit ID cannot be replayed through another factory relay
    When a client presents one factory Circuit ID through another factory relay
    Then the mismatched relay scope receives no address offer
