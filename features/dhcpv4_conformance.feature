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

  @negative @offer_hold @ipv4_should_next @reference_offer_hold_divergence
  Scenario: An unselected offer remains reserved for the original client
    Given the DHCP server is running
    When one DHCPv4 client leaves an offered address unselected
    And multiple DHCPv4 clients request that held address during the hold window
    Then every competing client is offered a different address
    And the original client can still select the held address

  @ipv4 @negative @known_divergence @non_compliance @ipv4_should_next_divergence
  Scenario: Reference servers expose their unreserved offer behavior
    Given the DHCP server is running
    When one DHCPv4 client leaves an offered address unselected
    And multiple DHCPv4 clients request that held address during the hold window
    Then the reference server reoffers the held address

  @negative @offer_hold_boundary @capability @requires_offer_hold_expiry
  Scenario: Offer hold protects concurrent contenders until its expiry boundary
    Given the DHCP server is running
    When one DHCPv4 client leaves an offered address unselected
    And concurrent DHCPv4 contenders request the held address before expiry
    Then no pre-expiry contender is offered the held address
    When the configured offer hold expires and a new concurrent wave requests the address
    Then exactly one post-expiry contender is offered the released candidate
    And the winning contender commits the address without an active duplicate

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
  Scenario: Every DHCPv4 client message family rejects bounded wire mutations safely
    Given a DHCPv4 client holds an active lease for malformed mutation checks
    When a deterministic corpus of malformed DHCPv4 messages is sent
    Then no malformed DHCPv4 transaction receives an OFFER ACK or NAK
    And the DHCPv4 lease targeted by malformed messages remains renewable
    And a valid DHCPv4 client still completes DORA

  @negative @malformed @bounded_fuzz @focused_robustness @reference_malformed_option_tail_divergence
  Scenario: Malformed trailing options invalidate every DHCPv4 client message family
    Given a DHCPv4 client holds an active lease for malformed mutation checks
    When every DHCPv4 message family carries malformed trailing option metadata
    Then no malformed trailing DHCPv4 option is accepted
    And the DHCPv4 lease targeted by malformed messages remains renewable

  @kea @known_divergence @non_compliance @malformed @bounded_fuzz @malformed_option_tail_divergence
  Scenario: Kea processes a valid DHCPv4 prefix before malformed trailing options
    Given a DHCPv4 client holds an active lease for malformed mutation checks
    When every DHCPv4 message family carries malformed trailing option metadata
    Then the reference server exposes its malformed trailing-option behavior
    And malformed trailing metadata can invalidate the targeted DHCPv4 binding
    And a valid DHCPv4 client still completes DORA

  @churn @focused_robustness
  Scenario: Repeated bounded lease churn preserves allocation safety
    Given the DHCP server is running
    When bounded DHCPv4 clients repeatedly acquire and release leases
    Then every churn transaction completed without duplicate active addresses
