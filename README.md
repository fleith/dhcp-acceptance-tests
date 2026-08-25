# DHCP Acceptance Tests

[![DHCP Acceptance Tests](https://github.com/fleith/dhcp-acceptance-tests/actions/workflows/ci.yml/badge.svg)](https://github.com/fleith/dhcp-acceptance-tests/actions/workflows/ci.yml)

Behavior-driven acceptance tests for DHCP servers using [Behave](https://behave.readthedocs.io/) and [Scapy](https://scapy.net/).

## Why Python + Behave?

- **BDD support:** Gherkin (Given/When/Then) makes DHCP scenarios read as executable requirements.
- **Rich networking libraries:** Scapy provides full control over packet construction and capture.
- **CI-friendly:** Runs entirely in Docker, no host configuration required.

## Running the tests

The recommended entrypoint is the helper script:

```bash
bash ./run_dhcp_tests.sh [--server isc-dhcpd|kea] [--ip-version v4|v6|dual] \
  [--server-version baseline|isc-final|kea-lts|kea-stable] [--tags TAG_EXPRESSION]...
```

Examples:

```bash
# Default: ISC DHCPv4
bash ./run_dhcp_tests.sh

# Kea DHCPv4
bash ./run_dhcp_tests.sh --server kea

# ISC DHCPv6
bash ./run_dhcp_tests.sh --ip-version v6

# Kea DHCPv6
bash ./run_dhcp_tests.sh --server kea --ip-version v6

# Run both v4 and v6 for one server
bash ./run_dhcp_tests.sh --server isc-dhcpd --ip-version dual

# Run the current stable Kea compatibility profile
bash ./run_dhcp_tests.sh --server kea --server-version kea-stable --ip-version dual

# Run explicitly quarantined known-divergence scenarios
bash ./run_dhcp_tests.sh --server kea --ip-version v4 --tags @known_divergence --tags @ipv4
bash ./run_dhcp_tests.sh --server kea --ip-version v6 --tags @known_divergence --tags @ipv6

# Exhaust a dedicated four-address DHCPv4 pool and verify release recovery
DHCPV4_POOL_START_OFFSET=190 DHCPV4_POOL_END_OFFSET=193 \
  DHCPV4_ALT_POOL_ENABLED=0 \
  bash ./run_dhcp_tests.sh --server kea --ip-version v4 --tags @pool_exhaustion
```

The script composes the correct Docker files and always tears down the stack after each run.
Pool exhaustion is excluded from ordinary runs and must be selected explicitly
with a bounded pool, as shown above.

Lifecycle and focused qualification checks have dedicated entrypoints:

```bash
# Persistent leases across graceful restart and SIGKILL recovery
bash ./run_lifecycle_tests.sh --server kea

# Overlap policy and unavailable lease-store startup behavior
bash ./run_config_safety_tests.sh --server isc-dhcpd --overlap-policy reject

# Runtime lease and option selection for accepted overlapping Kea subnets
bash ./run_overlap_lease_tests.sh --server kea --server-version kea-stable

# Bounded malformed corpus, concurrent deadline, and lease churn
bash ./run_dhcp_tests.sh --server kea --ip-version v4 --tags @focused_robustness

# Mixed allocation/renewal load with SIGKILL and durable-ACK recovery
bash ./run_stress_crash_tests.sh --server kea --server-version kea-stable --profile smoke

# Larger scheduled profile: 480 churn commits plus the crash/recovery waves
bash ./run_stress_crash_tests.sh --server kea --server-version kea-stable --profile scheduled

# Bounded lease soak with CPU, memory, PID, latency, and pool-reuse metrics
bash ./run_soak_tests.sh --server kea --server-version kea-stable --profile smoke

# Scheduled profile: 120 rounds x 24 clients = 2,880 lease commits
bash ./run_soak_tests.sh --server kea --server-version kea-stable --profile scheduled

# RFC 2131 server ping-check: silent candidate and responding candidate
bash ./run_ping_check_tests.sh --server isc-dhcpd
bash ./run_ping_check_tests.sh --server kea  # defaults to Kea 3.2

# IPv4 administrative logs, RFC 8925 addressless allocation, and live DDNS
bash ./run_ipv4_observability_tests.sh --server isc-dhcpd --server-version isc-final
bash ./run_ipv4_observability_tests.sh --server kea --server-version kea-stable

# DHCPv6 RFC 4704 FQDN negotiation and live AAAA lifecycle through Kea D2
bash ./run_dhcpv6_rfc4704_tests.sh

# RFC 9915 exact opaque Interface-ID policy through single and nested relays
bash ./run_dhcpv6_interface_id_tests.sh

# Exhaust isolated lease storage, force-kill, and reconcile durable ACKs
bash ./run_storage_fault_tests.sh --server isc-dhcpd
bash ./run_storage_fault_tests.sh --server kea --server-version kea-stable
```

Optional product capabilities are tagged `@capability` and skipped unless
explicitly advertised through `TEST_CAPABILITIES`. See
[`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) for adapter variables and the
claim boundary.

Version profiles keep the required distribution baseline while making upgrade
compatibility reproducible:

- `baseline`: pinned `networkboot/dhcpd:1.3.0` for ISC DHCP and Debian Bookworm's Kea packages.
- `isc-final`: Debian Bookworm's ISC DHCP 4.4.3-P1 final release line.
- `kea-lts`: the official ISC Kea 3.0.3 LTS images.
- `kea-stable`: the official ISC Kea 3.2.0 current stable images.

The RFC 8925 scenarios accept both standards-compliant server strategies: Kea
3.x's preferred addressless OFFER and the addressful fallback used by ISC DHCP
and Kea 2.2. An addressful response is followed through REQUEST/ACK; an
addressless response is not incorrectly requested by the test client.

The Kea 3.0.3 and 3.2.0 DHCPv6 profiles also abort on a malformed RELAY-FORWARD
that omits the mandatory Relay Message option. CI runs that robustness probe in
dedicated expected-divergence rows and excludes it only from the corresponding
full Kea 3.x IPv6 rows, allowing every other IPv6 scenario to finish.

Note: the deeper RFC 3011 alternate-subnet selection scenario currently runs on Kea only. It supplies a conflicting primary-pool Option 50 hint, verifies alternate-pool allocation, and requires byte-for-byte Option 118 preservation in OFFER and ACK. In this Docker topology, ISC DHCP accepts Option 118 but still allocates from the directly attached subnet rather than the selected alternate subnet. The default-disabled security test passes on ISC; Kea 2.2 instead honors Option 118 without an explicit enable switch and is recorded as a reference-backend divergence.

The strict unknown-client INIT-REBOOT test retransmits for an unbound same-subnet host outside all pools and reservations, then proves a valid client still completes DORA. ISC DHCP 4.4.3-P1 remains silent and passes; ISC DHCP 4.4.1 ACKs while Kea 2.2 and 3.2.0 NAK instead, so those profiles retain explicit divergence gates. ISC DHCP 4.4.1 similarly retains RFC 2131's historical omission of Client Identifier in replies; Kea and external targets run the RFC 6842 byte-for-byte echo assertion.

### Direct Docker Compose runs (advanced)

```bash
# DHCPv4 (ISC default)
docker compose up --abort-on-container-exit --exit-code-from test-runner

# DHCPv6 (ISC)
docker compose -f docker-compose.yml -f docker-compose.ipv6.yml up --abort-on-container-exit --exit-code-from test-runner

```

## Test environment variables

| Variable | Default | Description |
|---|---|---|
| `TEST_IP_VERSION` | `v4` | Test mode: `v4`, `v6`, or `dual` |
| `TEST_SERVER_IP` | `172.29.0.2` | DHCPv4 server IP |
| `TEST_SERVER_IPV6` | `fd00:29::2` | DHCPv6 server IP |
| `TEST_SERVER_IMPL` | `isc-dhcpd` | Backend selector for server-specific scenarios |
| `TEST_SERVER_VERSION` | `baseline` | Backend release profile used to scope known divergences |
| `TEST_INTERFACE` | `eth0` | Interface used for raw packets |
| `TEST_SUBNET` | detected from interface | Expected DHCPv4 lease subnet |
| `TEST_SUBNET_V6` | detected from interface | Expected DHCPv6 lease subnet |
| `TEST_SUBNET_SELECTION_SUBNET` | `172.29.1.0/24` | Alternate DHCPv4 subnet used by RFC 3011 selection tests |
| `TEST_DHCPV4_RELAY_SUBNET` | `172.29.2.0/24` | Independently selected relay subnet used for real `giaddr` scope tests |
| `DHCPV4_FQDN_SUFFIX` | `dhcp-acceptance.test` | Qualifying suffix used to complete partial RFC 4702 Client FQDN names |
| `DHCPV4_DDNS_SERVER_IP` | empty | Authoritative DNS update target used by the isolated ISC DHCP DDNS profile |
| `DHCPV4_SERVER_LOG_FILE` | empty | Server-side path for an observable DHCPv4 administrative event log |
| `TEST_DHCPV4_SERVER_LOG_FILE` | `/app/test-state/dhcpv4-server.log` | Test-runner view of the administrative event log |
| `TEST_DNS_SERVER` | empty | Authoritative DNS server queried by advertised DDNS capability scenarios |
| `TEST_LEASE_TIME` | `120` | Lease duration in seconds |
| `DHCPV6_RAPID_COMMIT` | `1` | Reference-fixture switch; set to `0` only through the isolated unknown-REBIND policy runner |
| `DHCPV6_DDNS_MANAGER_IP` | `127.0.0.1` | Kea D2 NameChangeRequest target; the isolated RFC 4704 profile supplies `172.29.0.5` |
| `DHCPV6_DDNS_SUFFIX` | `dhcp-acceptance.test` | Qualifying suffix used for partial DHCPv6 Client FQDN names |
| `DHCPV6_VALID_LIFETIME` | `120` | DHCPv6 valid lifetime; the isolated RFC 4704 expiry profile uses 12 seconds |
| `TEST_RFC4704_DDNS_EXPIRY_TIMEOUT` | `30` | Maximum post-expiry wait for authoritative AAAA cleanup |
| `TEST_DHCPV6_FORGED_OWNERSHIP_TIMEOUT` | `4` | Maximum seconds to observe a forged IA_NA REQUEST or REBIND response |
| `DHCPV6_INTERFACE_ID_POLICY` | `0` | Enables the isolated Kea exact Interface-ID pool policy when set to `1` |
| `DHCPV6_INTERFACE_ID_A_HEX` | `00ff706f72742d418000` | Complete opaque binary Interface-ID assigned to policy pool A |
| `DHCPV6_INTERFACE_ID_B_HEX` | `817669662d42007f` | Different-length opaque binary Interface-ID assigned to policy pool B |
| `TEST_CLIENT_MAC` | `02:00:00:00:00:01` | Fallback DHCPv4 client MAC |
| `TEST_RESULTS_DIR` | `/app/test-results/default` | JUnit report directory inside the test runner |
| `DHCPV4_POOL_START_OFFSET` | `100` | First /24 host offset in the primary DHCPv4 pool |
| `DHCPV4_POOL_END_OFFSET` | `200` | Last /24 host offset in the primary DHCPv4 pool |
| `DHCPV4_ALT_POOL_ENABLED` | `1` | Set to `0` only in isolated exhaustion runs so the RFC 3011 alternate pool cannot provide fallback capacity |
| `DHCPV4_RELAY_POLICY_CIRCUIT` | `slot=01/port=007` | Exact opaque Circuit ID that activates the RFC 3046 relay policy fixture |
| `DHCPV4_RELAY_POLICY_DOMAIN` | `opaque-circuit.acceptance.test` | Domain option returned only for the exact relay-policy Circuit ID |
| `RFC3442_EXTRA_ROUTE_COUNT` | `30` | Extra /24 routes that force Classless Static Route option 121 above 255 octets |
| `RFC8925_WAIT` | `1800` | Configured IPv6-Only Preferred wait; the isolated zero-default profile sets this to `0` |
| `TEST_DHCPV4_EXHAUSTION_LIMIT` | `16` | Safety limit for an explicitly selected pool-exhaustion run |
| `TEST_DHCPV4_CONCURRENT_CLIENTS` | `8` | Bounded number of simultaneous DHCPv4 clients (2..32) |
| `TEST_DHCPV4_BATCH_DEADLINE` | `15` | Maximum seconds for the bounded concurrent batch |
| `TEST_DHCPV4_OFFER_HOLD_SECONDS` | `0.75` | Minimum observation window during which competing clients must not receive an unselected offer |
| `TEST_DHCPV4_CHURN_CYCLES` | `12` | Bounded acquire/release churn cycles (2..64) |
| `TEST_DHCPV4_FUZZ_CASES` | `24` | Deterministic malformed corpus size (5..128) |
| `TEST_DHCPV4_PING_CHECK_ADDRESS` | empty | Candidate address used only by the isolated server ping-check runner |
| `DHCPV4_OVERLAP_ORDER` | `primary-first` | Kea fixture order: `primary-first` or `specific-first` |
| `TEST_DHCPV4_OVERLAP_EXPECTED_POOL_START` | empty | First address expected from the selected scope in an isolated overlap run |
| `TEST_DHCPV4_OVERLAP_EXPECTED_POOL_END` | empty | Last address expected from the selected scope in an isolated overlap run |
| `TEST_DHCPV4_OVERLAP_LOSING_HINT` | empty | Requested-address hint from the non-selected overlapping scope |
| `TEST_DHCPV4_OVERLAP_EXPECTED_DOMAIN` | empty | Domain-name marker proving which overlapping scope supplied response policy |
| `TEST_DHCPV4_OVERLAP_EXPECTED_SCOPE` | empty | Human-readable selected-scope label used in overlap assertion failures |
| `TEST_DHCPV4_STRESS_PREPARE_CLIENTS` | `32` | Active bindings committed and recorded before the orchestrated crash |
| `TEST_DHCPV4_STRESS_INFLIGHT_CLIENTS` | `24` | New clients requesting leases while the server is SIGKILLed |
| `TEST_DHCPV4_STRESS_POST_CLIENTS` | `8` | Fresh clients admitted after recovery without duplicating active bindings |
| `TEST_DHCPV4_STRESS_CHURN_ROUNDS` | `2` | Acquire/release rounds completed before the durable active batch |
| `TEST_DHCPV4_STRESS_CHURN_BATCH` | `8` | Clients committed in each pre-crash churn round |
| `TEST_DHCPV4_STRESS_CRASH_LOAD_SECONDS` | `3` | Maximum mixed allocation, renewal, and retransmission window around SIGKILL |
| `TEST_DHCPV4_STRESS_CAPTURE_TIMEOUT` | `10` | Maximum seconds to collect a complete stress response batch |
| `TEST_DHCPV4_STRESS_BATCH_DEADLINE` | `20` | Maximum elapsed seconds for one completed stress DORA batch |
| `TEST_DHCPV4_STRESS_P95_LIMIT_MS` | `3000` | Maximum combined response-latency p95 for completed transactions |
| `TEST_DHCPV4_STRESS_POOL_CAPACITY` | `101` | Safety check preventing a profile from exceeding the isolated pool |
| `TEST_DHCPV4_SOAK_ROUNDS` | `8` | Acquire/release rounds in the bounded soak (2..1000) |
| `TEST_DHCPV4_SOAK_BATCH_SIZE` | `16` | Batched clients committed and released per soak round |
| `TEST_DHCPV4_SOAK_POST_BATCH_SIZE` | `8` | Fresh clients used for the post-soak availability check |
| `TEST_DHCPV4_SOAK_POOL_CAPACITY` | `101` | Isolated pool size used to require and validate released-address reuse |
| `TEST_DHCPV4_SOAK_RELEASE_SETTLE_SECONDS` | `0.2` | Delay after each release batch before the next round |
| `TEST_DHCPV4_SOAK_CAPTURE_TIMEOUT` | `10` | Maximum seconds to collect each OFFER or ACK response batch |
| `TEST_DHCPV4_SOAK_BATCH_DEADLINE` | `20` | Maximum elapsed seconds for each completed DORA batch |
| `TEST_DHCPV4_SOAK_P95_LIMIT_MS` | `3000` | Maximum overall DHCP response-latency p95 |
| `TEST_DHCPV4_SOAK_LATENCY_GROWTH_LIMIT_MS` | `500` | Maximum late-window p95 increase over the early-window p95 |
| `TEST_DHCPV4_SOAK_MEMORY_GROWTH_LIMIT_MIB` | `64` | Maximum final server-memory increase over the pre-soak sample |
| `TEST_DHCPV4_SOAK_PIDS_GROWTH_LIMIT` | `8` | Maximum final server PID-count increase over the pre-soak sample |
| `TEST_DHCPV4_STORAGE_BASELINE_CLIENTS` | `10` | Durable clients recorded before isolated lease storage is exhausted |
| `TEST_DHCPV4_STORAGE_POOL_CAPACITY` | `11` | Safety check for the dedicated storage-fault pool |
| `TEST_DHCPV4_STORAGE_FAULT_TIMEOUT` | `4` | Maximum seconds to capture the transaction attempted under `ENOSPC` |
| `TEST_DHCPV4_STORAGE_RECOVERY_TIMEOUT` | `10` | Maximum seconds to reconcile durable owners after forced restart |
| `TEST_CAPABILITIES` | empty | Comma-separated optional capabilities to enable |

## Coverage snapshot

Server-focused coverage spans 12 RFCs: the existing eight plus RFC 3442,
RFC 4361, RFC 4704, and RFC 8925.

- **RFC 2131**: DORA flow, release, renew, rebinding edge cases, INIT-REBOOT, INFORM (including raw omission of lease timing options), NAK/DECLINE handling with exact administrative-log evidence, byte-identical initialization-parameter reuse after release, timed multi-client offer-hold enforcement, plus isolated server-side ICMP probing that offers a silent candidate and withholds a responding candidate. ISC DHCP 4.4.1, ISC DHCP 4.4.3-P1, and Kea references reoffer an unselected address; that behavior is captured as a known divergence while external targets run the strict check.
- **RFC 2131 pool capacity**: a dedicated bounded run exhausts the DHCPv4 pool, verifies that an additional client receives no offer, releases one lease, and proves the waiting client can acquire that address.
- **RFC 2132**: required network options, raw Subnet Mask/Router ordering, multi-address DNS encoding, and exact lease-time option length alongside T1/T2 timer validation.
- **RFC 3011**: default-disabled Subnet Selection posture, Option 118 acceptance, and the alternate-subnet selection path with a conflicting primary-pool address hint plus exact response echo on Kea in the multi-subnet Docker topology.
- **RFC 3046**: Relay Agent Information (Option 82) echo, byte preservation, last-option ordering, omission for ordinary clients, direct unicast renewal handling, opaque Circuit-ID policy matching, and raw validation that relay metadata never moves into overloaded BOOTP fields.
- **RFC 3396**: semantic request-fragment reassembly through class policy plus exact reconstruction of a 320-octet response option split into sequential fragments. Kea 2.2's request-policy divergence is explicitly documented.
- **RFC 3442**: Classless Static Route Option delivery, route decoding, classless default-route encoding, suppression of requested legacy Router and Static Route options, unusual parameter request lists, and exact RFC 3396 reconstruction of an oversized option 121. Kea 2.2 still returns legacy Router option 3, while Kea 3.0.3 and 3.2.0 reject the oversized option instead of splitting it; both behaviors are recorded explicitly.
- **RFC 4361**: node-specific DHCPv4 client identifiers, stable identity across hardware changes, IAID/DUID isolation, and malformed identifier recovery.
- **RFC 4702**: Client FQDN option negotiation with raw DNS/ASCII encoding and E-flag preservation, a capability-gated unsupported-ASCII ignore path, exact partial-name completion, conflicting Host Name precedence, and DNS/ASCII response RCODE validation. The required ISC DHCP observability profile uses a live authoritative DNS observer to prove that updates wait for lease commitment, Option 81 is published, and the conflicting Option 12 name is ignored. Kea 2.2 and 3.2.0 return `0/0` rather than `255/255` in DHCPOFFER for both encodings; that divergence is recorded explicitly.
- **RFC 4704**: DHCPv6 Client FQDN negotiation with strict DNS-wire decoding, complete configured suffixes, legal flag negotiation, nonzero MBZ input clearing, and exact name stability through RENEW. An isolated Kea D2 profile proves that AAAA publication waits for REQUEST/REPLY and that server-created records are deleted after RELEASE and short-lease reclamation. ISC runs only the universal omission checks in this fixture; a tagged, default-excluded divergence documents Kea 2.2 returning FQDN without an ORO request.
- **RFC 6842**: client-identifier based lease stability across hardware-address changes, byte-for-byte response echo when supplied, and response omission when absent. ISC DHCP 4.4.1's legacy reply omission is recorded as a backend-specific divergence.
- **RFC 8925**: requested IPv6-mostly scope delivery, configured and zero-default timer encoding, addressless and addressful server strategies, addressful fallback completion, request-list stability, omission on an independently selected non-IPv6-mostly relay pool, Rapid Commit suppression, and an isolated Kea 3.2 proof that an addressless response neither probes nor consumes any bounded-pool candidate.
- **RFC 9915**: DHCPv6 lease acquisition, lifetime validation, RENEW, REBIND, RELEASE, DECLINE, stateless INFORMATION-REQUEST, IA_PD prefix delegation, CONFIRM status handling, relay-forward/relay-reply address assignment, hop-count boundaries, nested relay paths, Interface-ID preservation and exclusion from direct messages, Reconfigure-Accept signaling, and malformed or unauthorized message recovery. An isolated Kea profile now guards two pools with complete opaque Interface-ID byte strings containing zero and high-bit octets; exact A/B values, truncated/extended/bit-flipped/unknown values, split duplicate options, and both nested relay orders prove exact matching and closest-client relay scope through both offer and lease commitment. Reply validation checks exact identifiers for CONFIRM, RENEW, and INFORMATION-REQUEST, plus equal IA_NA/IA_PD renewal timers. The strict ownership tests reject forged IA_NA REQUEST and REBIND claims, while explicit divergence scenarios record that ISC DHCP and Kea reassign the active address during forged REBIND. Rapid Commit-enabled and disabled policy paths are both executable; the references' disabled-policy omission of `NoBinding` is also recorded. Representative reserved-IID hints and a bounded allocation sample cover address-generation edges without claiming exhaustive unpredictability. Authenticated server-initiated Reconfigure remains outside the fixture's claims.

Additional coverage is intentionally excluded from the 12-RFC server count:

- **RFC 5227**: client-companion IPv4 Address Conflict Detection, including conflict, no-conflict, and DHCPDECLINE paths; this is not DHCP server compliance coverage.
- **RFC 4039**: unsupported DHCPv4 Rapid Commit fallback and malformed-option recovery, tagged as non-compliance coverage; neither backend claims RFC 4039 support.

Beyond the RFC packet flows, the qualification profile now covers duplicate
transactions, concurrent clients, real `giaddr` relay forwarding with exact
Option 82 preservation, reservations, client classes, bounded malformed input,
load deadlines, churn, persistence, crash recovery, and configuration safety.
The isolated stress/crash profiles add sustained acquire/release batches and
mixed allocation, renewal, and retransmission traffic during SIGKILL. Every
ACK observed before process death must recover for the same client; fresh
post-restart clients must not receive any active recorded address. The runner
also emits JSON p50/p95/p99 latency and transaction-count metrics with JUnit.
The scheduled DHCPv4 soak adds repeated acquire/release rounds that exceed the
pool capacity cumulatively, proving that released addresses return safely to
service. It compares early and late latency windows, verifies availability
after the final round, and records server CPU, memory, and PID measurements.
Configured growth limits catch bounded resource regressions; the measurements
remain environment-specific and are not portable capacity numbers.
The runtime storage-fault profile fills a disposable 32 MiB lease filesystem,
records the final transaction outcome, force-kills the server, restores
capacity, and requires every pre-fault binding plus every fault-time ACK to
survive with exact client/address ownership. A server that does not ACK under
the fault must admit that client safely after recovery. The filler is capped
at 64 MiB and the test volume is deleted after each run.
For backends that accept overlapping subnets, the isolated Kea profile also
checks that both declaration orders retain the reference selection result,
OFFER-to-ACK scope consistency, scope-specific options, and rejection of
requested-address hints from the non-selected pool.
Reload, HA, a second direct interface, and authenticated DHCPv6 Reconfigure
have executable capability-gated scenarios because they require a
product-specific topology or control-plane adapter. External services may use
the DDNS and storage-fault capability adapters, while ISC DHCP runs the bundled
authoritative DNS profile and both reference families run the bundled isolated
storage profile in CI. The machine-readable index is
[`docs/conformance-profile.json`](docs/conformance-profile.json).
The statement-level [RFC MUST/SHOULD traceability matrix](docs/RFC_REQUIREMENTS.md)
maps each inventoried requirement to an exact scenario or explicit gap; its
machine-readable source is
[`docs/rfc-requirements.csv`](docs/rfc-requirements.csv).

## Project structure

```
dhcp-acceptance-tests/
|-- dhcp/
|   |-- Dockerfile
|   |-- entrypoint.sh
|   `-- entrypoint_v6.sh
|-- kea/
|   |-- Dockerfile
|   |-- entrypoint.sh
|   `-- entrypoint_v6.sh
|-- features/
|   |-- dhcp_lease.feature
|   |-- dhcp_renewal.feature
|   |-- dhcp_options.feature
|   |-- dhcp_nak_decline.feature
|   |-- dhcp_init_reboot.feature
|   |-- dhcp_inform.feature
|   |-- dhcp_address_pool.feature
|   |-- dhcp_rfc3011_subnet_selection.feature
|   |-- dhcp_rfc2131_server_ping_check.feature
|   |-- dhcp_rfc3046_relay_agent.feature
|   |-- dhcp_rfc3396_option_concat.feature
|   |-- dhcp_rfc3442_classless_routes.feature
|   |-- dhcp_rfc4039_rapid_commit_fallback.feature
|   |-- dhcp_rfc4361_node_client_id.feature
|   |-- dhcp_rfc4702_client_fqdn.feature
|   |-- dhcp_rfc5227_address_conflict_detection.feature
|   |-- dhcp_rfc6842_client_identifier.feature
|   |-- dhcp_rfc8925_ipv6_only_preferred.feature
|   |-- dhcpv6_decline.feature
|   |-- dhcpv6_confirm.feature
|   |-- dhcpv6_information.feature
|   |-- dhcpv6_lease.feature
|   |-- dhcpv6_lifetimes.feature
|   |-- dhcpv6_prefix_delegation.feature
|   |-- dhcpv6_rebind.feature
|   |-- dhcpv6_reconfigure.feature
|   |-- dhcpv6_relay.feature
|   |-- dhcpv6_release.feature
|   |-- dhcpv6_rfc4704_client_fqdn.feature
|   |-- dhcpv4_conformance.feature
|   |-- dhcpv4_persistence.feature
|   |-- dhcpv4_relay_conformance.feature
|   |-- optional_service_capabilities.feature
|   |-- dhcpv6_optional_capabilities.feature
|   |-- environment.py
|   `-- steps/
|       |-- dhcp_steps.py
|       |-- dhcpv4_support.py
|       |-- dhcp_pool_exhaustion_steps.py
|       |-- dhcp_ping_check_steps.py
|       |-- dhcp_rfc3442_steps.py
|       |-- dhcp_rfc4039_steps.py
|       |-- dhcp_rfc4361_steps.py
|       |-- dhcp_rfc5227_steps.py
|       |-- dhcp_rfc8925_steps.py
|       |-- dhcpv6_decline_steps.py
|       |-- dhcpv6_confirm_steps.py
|       |-- dhcpv6_information_steps.py
|       |-- dhcpv6_lifetime_steps.py
|       |-- dhcpv6_prefix_delegation_steps.py
|       |-- dhcpv6_rebind_steps.py
|       |-- dhcpv6_reconfigure_steps.py
|       |-- dhcpv6_relay_steps.py
|       |-- dhcpv6_rfc4704_steps.py
|       |-- dhcpv6_release_steps.py
|       |-- dhcpv6_steps.py
|       `-- dhcpv6_support.py
|-- docker-compose.yml
|-- docker-compose.kea.yml
|-- docker-compose.ipv6.yml
|-- docker-compose.ddns.yml
|-- docker-compose.ipv6-ddns.yml
|-- docker-compose.ipv6-interface-id.yml
|-- RFC_EXPANSION_PLAN.md
|-- run_dhcp_tests.sh
|-- run_lifecycle_tests.sh
|-- run_config_safety_tests.sh
|-- run_ping_check_tests.sh
|-- run_ipv4_observability_tests.sh
|-- run_dhcpv6_rfc4704_tests.sh
|-- run_dhcpv6_interface_id_tests.sh
|-- run_tests.py
|-- summarize_junit.py
|-- tests/test_summarize_junit.py
|-- .github/workflows/ci.yml
`-- requirements.txt
```

## CI

GitHub Actions runs the supported matrix:

- `isc-dhcpd` with `v4` and `v6`
- `kea` with `v4` and `v6`

These four baseline jobs are required. A separate compatibility matrix covers
ISC DHCP 4.4.3-P1, Kea 3.0.3 LTS, Kea 3.2.0 stable, and explicitly tagged known
divergences. The Kea 3.x malformed DHCPv6 relay crash is isolated in dedicated
robustness rows so it cannot truncate the full IPv6 runs. Unclassified
compatibility failures still fail their job.

CI also runs bounded focused robustness, lifecycle/crash recovery,
configuration-safety policy, pool exhaustion, RFC 2131 server ping-check,
IPv4 administrative/addressless/DDNS observability, DHCPv6 RFC 4704 live-DDNS
lifecycle checks, exact opaque DHCPv6 Interface-ID policy checks on Kea 3.0.3
and 3.2.0, and validation of the coverage profile.
Other capability-gated scenarios remain deployment jobs: a target service must
supply the advertised capability and its adapter configuration.

Every matrix row writes a Markdown summary and uploads its JUnit reports for 14
days, including failed runs. The full workflow also runs every Monday and can
be started manually from GitHub.
