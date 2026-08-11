@rfc5227 @client-companion
Feature: RFC 5227 companion IPv4 Address Conflict Detection
  These scenarios exercise the Address Conflict Detection behavior expected of a
  DHCP client after DHCPACK and before it uses an acknowledged address. They are
  companion coverage and do not claim that the DHCP server implements RFC 5227.

  Background:
    Given the DHCP server is running

  Scenario: A conflicting address claim causes DHCPDECLINE and a new offer
    When an RFC 5227 companion client completes DORA with a transaction-specific DHCPACK
    And the companion probes while a distinct peer claims the acknowledged address
    Then the companion detects an address conflict
    And the companion stops probing after the conflict decision
    When the companion sends DHCPDECLINE for the conflicted acknowledged address
    Then the same client receives a different transaction-specific DHCPOFFER

  Scenario: A simultaneous probe for the acknowledged address is a conflict
    When an RFC 5227 companion client completes DORA with a transaction-specific DHCPACK
    And the companion probes while a distinct peer probes the acknowledged address
    Then the companion detects an address conflict
    And the companion stops probing after the conflict decision
    When the companion sends DHCPDECLINE for the conflicted acknowledged address
    Then the same client receives a different transaction-specific DHCPOFFER

  @negative
  Scenario: Unrelated ARP traffic does not reject the acknowledged address
    When an RFC 5227 companion client completes DORA with a transaction-specific DHCPACK
    And the companion probes while unrelated ARP traffic occurs
    Then the companion does not detect an address conflict
    And the companion completes the RFC 5227 probe and monitoring sequence
    And the companion did not send DHCPDECLINE
    Then the companion accepts and announces the acknowledged address

  @negative
  Scenario: A self-originated address claim does not reject the acknowledged address
    When an RFC 5227 companion client completes DORA with a transaction-specific DHCPACK
    And the companion probes while its own address claim is observed
    Then the companion does not detect an address conflict
    And the companion completes the RFC 5227 probe and monitoring sequence
    And the companion did not send DHCPDECLINE
    Then the companion accepts and announces the acknowledged address
