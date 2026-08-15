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
bash ./run_dhcp_tests.sh --server kea --ip-version v6 --tags @known_divergence

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

# RFC 2131 server ping-check: silent candidate and responding candidate
bash ./run_ping_check_tests.sh --server isc-dhcpd
bash ./run_ping_check_tests.sh --server kea  # defaults to Kea 3.2
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

The Kea 3.x IPv4 profiles currently expose an RFC 8925 behavior change: option
108 requests receive an addressless OFFER instead of completing the suite's
deliberate IPv4 fallback flow. This remains visible in the informational matrix
as an expected compatibility warning. Any unrelated failure in the same job is
still treated as a regression.

The Kea 3.0.3 and 3.2.0 DHCPv6 profiles also abort on a malformed RELAY-FORWARD
that omits the mandatory Relay Message option. CI runs that robustness probe in
dedicated expected-divergence rows and excludes it only from the corresponding
full Kea 3.x IPv6 rows, allowing every other IPv6 scenario to finish.

Note: the deeper RFC 3011 alternate-subnet selection scenario currently runs on Kea only. In this Docker topology, ISC DHCP accepts Option 118 but still allocates from the directly attached subnet rather than the selected alternate subnet.

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
| `TEST_INTERFACE` | `eth0` | Interface used for raw packets |
| `TEST_SUBNET` | detected from interface | Expected DHCPv4 lease subnet |
| `TEST_SUBNET_V6` | detected from interface | Expected DHCPv6 lease subnet |
| `TEST_SUBNET_SELECTION_SUBNET` | `172.29.1.0/24` | Alternate DHCPv4 subnet used by RFC 3011 selection tests |
| `TEST_LEASE_TIME` | `120` | Lease duration in seconds |
| `TEST_CLIENT_MAC` | `02:00:00:00:00:01` | Fallback DHCPv4 client MAC |
| `TEST_RESULTS_DIR` | `/app/test-results/default` | JUnit report directory inside the test runner |
| `DHCPV4_POOL_START_OFFSET` | `100` | First /24 host offset in the primary DHCPv4 pool |
| `DHCPV4_POOL_END_OFFSET` | `200` | Last /24 host offset in the primary DHCPv4 pool |
| `DHCPV4_ALT_POOL_ENABLED` | `1` | Set to `0` only in isolated exhaustion runs so the RFC 3011 alternate pool cannot provide fallback capacity |
| `TEST_DHCPV4_EXHAUSTION_LIMIT` | `16` | Safety limit for an explicitly selected pool-exhaustion run |
| `TEST_DHCPV4_CONCURRENT_CLIENTS` | `8` | Bounded number of simultaneous DHCPv4 clients (2..32) |
| `TEST_DHCPV4_BATCH_DEADLINE` | `15` | Maximum seconds for the bounded concurrent batch |
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
| `TEST_CAPABILITIES` | empty | Comma-separated optional capabilities to enable |

## Coverage snapshot

Server-focused coverage spans 12 RFCs: the existing eight plus RFC 3442,
RFC 4361, RFC 4704, and RFC 8925.

- **RFC 2131**: DORA flow, release, renew, rebinding edge cases, INIT-REBOOT, INFORM, NAK/DECLINE handling, plus isolated server-side ICMP probing that offers a silent candidate and withholds a responding candidate.
- **RFC 2131 pool capacity**: a dedicated bounded run exhausts the DHCPv4 pool, verifies that an additional client receives no offer, releases one lease, and proves the waiting client can acquire that address.
- **RFC 2132**: required network options and T1/T2 lease timer validation.
- **RFC 3011**: Subnet Selection Option (option 118) acceptance on ISC and Kea, plus alternate-subnet selection path on Kea in the multi-subnet Docker topology.
- **RFC 3046**: relay-agent-information (Option 82) request acceptance path.
- **RFC 3396**: concatenated option fragment acceptance path.
- **RFC 3442**: Classless Static Route Option delivery, route decoding, classless default-route encoding, and unusual parameter request lists.
- **RFC 4361**: node-specific DHCPv4 client identifiers, stable identity across hardware changes, IAID/DUID isolation, and malformed identifier recovery.
- **RFC 4702**: Client FQDN option (Option 81) negotiation - server echoes the option in its DHCPACK.
- **RFC 4704**: DHCPv6 Client FQDN negotiation. Kea runs the positive negotiation scenarios; ISC runs only the universal omission checks in this fixture. A tagged, default-excluded known divergence documents that Kea 2.2 returns FQDN without an ORO request.
- **RFC 6842**: client-identifier based lease stability across different hardware addresses.
- **RFC 8925**: requested IPv6-Only Preferred option delivery, timer encoding, deliberate IPv4 fallback processing, request-list stability, and subnet/client omission behavior.
- **RFC 9915**: DHCPv6 lease acquisition, lifetime validation, RENEW, REBIND, RELEASE, DECLINE, stateless INFORMATION-REQUEST, IA_PD prefix delegation, CONFIRM status handling, relay-forward/relay-reply address assignment, hop-count boundaries, nested relay paths, Interface-ID preservation, Reconfigure-Accept signaling, and malformed or unauthorized message recovery. Authenticated server-initiated Reconfigure remains outside the fixture's claims. IA_PD and these lifecycle paths deepen existing RFC coverage rather than adding another RFC to the count.

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
For backends that accept overlapping subnets, the isolated Kea profile also
checks that both declaration orders retain the reference selection result,
OFFER-to-ACK scope consistency, scope-specific options, and rejection of
requested-address hints from the non-selected pool.
Reload, HA, DDNS, a second direct interface, and authenticated DHCPv6
Reconfigure, plus runtime lease-storage fault injection, have executable
capability-gated scenarios because they require a product-specific topology or
control-plane adapter. The machine-readable index is
[`docs/conformance-profile.json`](docs/conformance-profile.json).

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
|-- RFC_EXPANSION_PLAN.md
|-- run_dhcp_tests.sh
|-- run_lifecycle_tests.sh
|-- run_config_safety_tests.sh
|-- run_ping_check_tests.sh
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
divergences. The documented Kea 3.x RFC 8925 difference is reported as a
warning. The Kea 3.x malformed DHCPv6 relay crash is isolated in dedicated
robustness rows so it cannot truncate the full IPv6 runs. Unclassified
compatibility failures still fail their job.

CI also runs bounded focused robustness, lifecycle/crash recovery,
configuration-safety policy, pool exhaustion, RFC 2131 server ping-check on
ISC DHCP and Kea 3.2, and validation of the coverage profile. Other
capability-gated scenarios remain deployment jobs: a target service must
supply the advertised capability and its adapter configuration.

Every matrix row writes a Markdown summary and uploads its JUnit reports for 14
days, including failed runs. The full workflow also runs every Monday and can
be started manually from GitHub.
