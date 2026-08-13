@ipv4 @conformance
Feature: DHCPv4 transaction safety and configuration behavior
  A conforming server must preserve one binding across retransmissions, keep
  simultaneous clients isolated, and apply configured identity and class
  policy without leaking state between transactions.

  @negative @retransmission
  Scenario: Retransmitted DISCOVER and REQUEST remain idempotent
    Given the DHCP server is running
    When one DHCPv4 client retransmits the same DISCOVER
    Then every matching offer is an uncommitted pool candidate
    When that client retransmits the matching REQUEST
    Then every matching acknowledgement preserves one binding
    And another DHCPv4 client receives a distinct active lease

  @concurrency
  Scenario: Concurrent clients receive independent bindings
    Given the DHCP server is running
    When multiple DHCPv4 clients acquire leases concurrently
    Then every concurrent client has one unique active binding

  @concurrency @load @focused_robustness
  Scenario: A bounded concurrent batch completes within its service deadline
    Given the DHCP server is running
    When multiple DHCPv4 clients acquire leases concurrently
    Then every concurrent client has one unique active binding
    And the concurrent DHCPv4 batch completes within the configured deadline

  @reservation
  Scenario: A configured hardware reservation is honored
    Given the DHCP server is running
    When the configured reserved DHCPv4 client acquires a lease
    Then the reserved client receives its configured address

  @client_class
  Scenario: A configured client class supplies class-specific options
    Given the DHCP server is running
    When a DHCPv4 client in the configured vendor class acquires a lease
    Then the class-specific domain option is present in OFFER and ACK

  @negative @malformed @bounded_fuzz @focused_robustness
  Scenario: A bounded malformed corpus cannot create a lease or poison the server
    Given the DHCP server is running
    When a deterministic corpus of malformed DHCPv4 messages is sent
    Then no malformed DHCPv4 transaction receives a DHCPACK
    And a valid DHCPv4 client still completes DORA

  @churn @focused_robustness
  Scenario: Repeated bounded lease churn preserves allocation safety
    Given the DHCP server is running
    When bounded DHCPv4 clients repeatedly acquire and release leases
    Then every churn transaction completed without duplicate active addresses
