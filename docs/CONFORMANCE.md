# DHCP service qualification profile

This repository tests concrete DHCP behaviors. It does not issue a blanket
standards-compliance certificate. A service may claim the rows it has executed
successfully, using the exact server version and configuration recorded with
the results.

The machine-readable coverage index is
[`conformance-profile.json`](conformance-profile.json). `covered` means that a
test is supplied and runs against its applicable bundled reference fixture(s),
with backend-specific scope stated in the evidence.
`conditional` means that the test is supplied but requires a service-specific
adapter or topology. `partial` means that more requirements analysis is still
needed before making a complete claim.

## Test levels

| Level | Invocation | Purpose |
|---|---|---|
| Required | `bash ./run_dhcp_tests.sh --server <server> --ip-version <version>` | Protocol flows and ordinary negative cases |
| Focused robustness | `bash ./run_dhcp_tests.sh --server <server> --ip-version v4 --tags @focused_robustness` | Bounded malformed corpus, concurrent load deadline, and churn |
| Stress/crash smoke | `bash ./run_stress_crash_tests.sh --server <server> --profile smoke` | PR-safe mixed allocation, renewal, retransmission, SIGKILL, and durable-ACK recovery |
| Scheduled stress/crash | `bash ./run_stress_crash_tests.sh --server <server> --profile scheduled` | 480 pre-crash churn commits plus larger active, in-flight, and recovery waves |
| Scheduled DHCPv4 soak | `bash ./run_soak_tests.sh --server <server> --profile scheduled` | 2,880 acquire/release commits, released-address reuse, latency drift, post-soak availability, and container resource growth |
| Pool exhaustion | Select `@pool_exhaustion` with a deliberately small pool | Exhaustion and recovery without making normal runs consume the entire pool |
| Server ping check | `bash ./run_ping_check_tests.sh --server <server>` | RFC 2131 candidate-address ICMP probing with silent and responding peers |
| IPv4 observability | `bash ./run_ipv4_observability_tests.sh --server <server>` | DECLINE administrative evidence plus Kea addressless allocation or ISC live DDNS behavior |
| DHCPv6 RFC 4704 | `bash ./run_dhcpv6_rfc4704_tests.sh [--server-version kea-lts\|kea-stable]` | Client FQDN wire/flag behavior plus authoritative AAAA timing, RELEASE cleanup, and expiry cleanup through Kea D2 |
| DHCPv6 Interface-ID policy | `bash ./run_dhcpv6_interface_id_tests.sh [--server-version kea-lts\|kea-stable]` | Exact opaque Option 18 pool selection and lease commitment, non-exact denial, closest-client nested-relay scope, and byte preservation |
| DHCPv6 authenticated Reconfigure | `TEST_RECONFIGURE_TRIGGER_COMMAND=<adapter> bash ./run_dhcpv6_reconfigure_tests.sh --compose-file <target-override>` | RKAP key negotiation, complete HMAC validation, opt-out, tamper/replay rejection, exact metadata, and post-trigger RENEW |
| DHCPv6 Preference | `bash ./run_dhcpv6_preference_tests.sh --server <server>` | Configured nonzero RFC 9915 server Preference, complementing the zero-default required check |
| DHCPv6 REBIND policy | `bash ./run_dhcpv6_rebind_policy_tests.sh --server <server>` | Documents the ISC/Kea omission of NoBinding with Rapid Commit disabled; strict target-service assertion remains available separately |
| DHCPv6 reserved-IID pools | `bash ./run_dhcpv6_reserved_iid_tests.sh` | Exhausts pools containing representative RFC-reserved IIDs and records Kea's reference divergence |
| DHCPv6 REQUEST regeneration | `bash ./run_dhcpv6_request_regeneration_tests.sh [--server-version kea-lts\|kea-stable]` | Bundled Kea adapter combines identical wire retransmission with exact-DUID, exact-transaction lease allocation/reuse event deltas; targets may replace the adapter and topology |
| DHCPv6 generation lifecycle | Supply the generation topology variables and run `bash ./run_dhcpv6_generation_lifecycle_tests.sh --compose-file <target-override>` | Two-subnet uniqueness, repeated persistent restarts, collision avoidance, exhaustion, release, and reuse |
| DHCPv4 offer-hold boundary | `TEST_DHCPV4_OFFER_HOLD_EXPIRY_SECONDS=<seconds> bash ./run_offer_hold_boundary_tests.sh --compose-file <target-override>` | Concurrent contender waves immediately before and after the configured expiry boundary |
| Overlapping leases | `bash ./run_overlap_lease_tests.sh --server kea` | Runtime pool and option selection in both accepted subnet declaration orders |
| Lifecycle | `bash ./run_lifecycle_tests.sh --server <server>` | Graceful restart, SIGKILL recovery, and persistent binding ownership |
| Configuration safety | `bash ./run_config_safety_tests.sh --server <server> [--overlap-policy reject\|allow]` | Explicit overlap policy and unavailable lease-store rejection |
| Runtime storage fault | `bash ./run_storage_fault_tests.sh --server <server>` | Exhaust an isolated lease filesystem, SIGKILL, and reconcile every ACK after recovery |
| Capability | Select `@capability` or one `@requires_*` tag and configure its adapter | Product features that cannot be assumed for every DHCP server |

The focused, stress/crash, and soak checks are deliberately bounded. They catch
correctness, latency, persistence, and basic resource regressions; they are not
a hardware capacity benchmark, multi-hour soak test, or a substitute for
product-specific sizing. The smoke profile runs on pushes and pull requests.
The larger profiles run on the scheduled workflow and manual dispatch.

The bounded DHCPv4 soak deliberately requests more leases over time than the
isolated pool could supply without reuse. Every round must commit unique active
addresses and release them; later rounds must reuse at least one released
address without conflict. Early and late response-latency windows are compared,
and a fresh batch must still complete after the soak. Concurrent host sampling
records server CPU, memory, and PID usage. Final memory and PID growth have
explicit regression limits, while CPU is reported for diagnosis rather than
treated as a portable pass/fail capacity threshold.

The stress/crash runner coordinates the client and host through explicit state
markers. It commits and records a durable batch, starts new allocation requests
plus renewals and retransmissions, and only then SIGKILLs the server. Every ACK
captured before death is recorded. After restart, the original clients must
reassert those exact addresses, and a fresh batch must avoid every active
binding. JSON metrics include transaction counts, batch duration, and p50,
p95, p99, and maximum response latency.

The runtime storage-fault runner mounts the lease database on a disposable
32 MiB ext4 loop filesystem and fills it to a verified `ENOSPC` condition.
Ten durable clients occupy all but one pool address before a final client
attempts to commit. The server is then killed without a graceful shutdown,
capacity is restored while it is stopped, and the service restarts. A
fault-time ACK is permitted only when that exact client/address binding
survives the crash; otherwise the unacknowledged client must commit safely
after recovery. All ten pre-fault owners must also retain their addresses.
The fixture is bounded to 64 MiB of filler data and deletes its test-only
volume on exit.

The server ping-check fixture uses separate one-address pools for its two
phases. A fixed link-layer neighbor makes the server's ICMP request observable:
the silent phase does not configure the candidate address and therefore sends
no Echo Reply, while the occupied phase configures it and lets the kernel
reply. ISC DHCP supports this directly. Kea uses its `libdhcp_ping_check.so`
hook; the Kea 2.2 baseline predates that hook, so the runner defaults to Kea
3.2 and rejects `--server-version baseline`.

The overlapping-lease fixture is intentionally separate from configuration
safety. ISC DHCP rejects the supplied overlap topology, so its correct behavior
remains covered by `run_config_safety_tests.sh`. Kea accepts the topology; the
runtime runner gives the `/24` and `/25` disjoint pools and distinct domain-name
markers, executes both declaration orders, and verifies that reordering alone
does not change the reference selection result. DHCPOFFER and DHCPACK must stay
in that selected scope. The runner also supplies a requested-address hint from
the losing scope and proves the hint cannot cross the selection boundary.

The IPv4 observability runner supplies the integration points that cannot be
proven from DHCP packets alone. Both reference families expose a server event
log and must identify the exact DHCPDECLINE address. Kea 3.2 additionally runs
an IPv6-mostly subnet with a bounded pool: the Option 108 response must offer
0.0.0.0 without an ICMP probe, after which ordinary clients must commit the
entire pool. ISC DHCP 4.4.3-P1 uses the bundled authoritative DNS observer to
prove that RFC 4702 updates occur only after ACK and that Option 81 suppresses
a conflicting Option 12 name.

The DHCPv6 RFC 4704 runner adds an isolated Kea D2 service and extends the
same authoritative observer to AAAA records. Kea must leave DNS unchanged at
ADVERTISE, publish only after REQUEST/REPLY, delete on RELEASE, and delete
again when the short test lease is reclaimed after expiry. Ordinary IPv6 runs
retain their normal lifetimes and do not depend on D2.

The DHCPv6 Interface-ID policy runner configures two class-guarded address
pools using full binary Option 18 equality at the relay closest to the client.
The configured values deliberately differ in length and include zero and
high-bit octets. Near matches, unknown values, and two separate Interface-ID
options whose payloads only match when incorrectly concatenated must receive no
address. Nested probes reverse the outer and inner values to prove that policy
uses the closest-client relay while every RELAY-REPLY layer preserves its own
opaque bytes through ADVERTISE and committed REPLY.

The reserved-IID runner changes allocator topology rather than relying only on
client hints. Its three tiny pools contain subnet-router anycast, modified
EUI-64, and highest-128 boundary values alongside known-safe addresses. The
strict target assertion requires the exact safe set after exhaustion. Kea
3.2.0 allocates reserved values from these explicit pools, so the reference
profile records that result as a known divergence instead of treating it as a
passing implementation.

## Capability adapters

Capabilities are skipped unless their name is present in the comma-separated
`TEST_CAPABILITIES` value. This prevents an absent optional feature from being
reported as a pass.

| Capability | Required configuration |
|---|---|
| `reload` | `TEST_RELOAD_COMMAND`; optionally `TEST_RELOADED_CLASS_DOMAIN` |
| `ha` | `TEST_HA_FAILOVER_COMMAND`; optionally `TEST_HA_RECOVER_COMMAND` |
| `ddns` | `TEST_DNS_SERVER` and optionally `TEST_DDNS_FQDN`; the bundled ISC profile supplies the DNS observer and server configuration |
| `dhcpv6_ddns` | `TEST_DNS_SERVER` plus a DHCPv6 server/D2 integration; the bundled Kea profile supplies D2, the authoritative observer, and short expiry timers |
| `rfc4702_ascii_unsupported` | Target service configured without legacy ASCII Option 81 support; the scenario requires DORA to succeed while both responses ignore Client FQDN |
| `dhcpv6_rapid_commit` | DHCPv6 server configured to accept Rapid Commit; the bundled IPv6 reference fixtures enable it and expose the capability by default |
| `dhcpv6_interface_id_policy` | DHCPv6 server with two pools guarded by exact closest-client Interface-ID matching; the bundled Kea runner supplies the policy and expected ranges |
| `dhcpv6_request_observability` | `TEST_DHCPV6_REQUEST_COUNTER_COMMAND`, which prints the cumulative number of matching REQUEST-processing events |
| `dhcpv6_generation_lifecycle` | `TEST_DHCPV6_GENERATION_RESTART_COMMAND`, two served subnets, a usable relay link address, and exact per-subnet pool capacity |
| `offer_hold_expiry` | `TEST_DHCPV4_OFFER_HOLD_EXPIRY_SECONDS`, set to the target's configured offer-hold duration; optionally tune contender count |
| `multi_interface` | `TEST_SECOND_INTERFACE`, `TEST_SECOND_SUBNET`, and `TEST_SECOND_SERVER_IP` |
| `authenticated_reconfigure` | `TEST_RECONFIGURE_TRIGGER_COMMAND`; optionally `TEST_RECONFIGURE_AUTH_VALIDATOR_COMMAND` for a second product-specific validation |
| `storage_fault` | `TEST_STORAGE_FAIL_COMMAND` and `TEST_STORAGE_RECOVER_COMMAND` for an external target; the bundled reference fixtures use `run_storage_fault_tests.sh` |

Adapter commands execute inside the test-runner container. For every trigger,
the Reconfigure adapter receives `TEST_RECONFIGURE_CLIENT_ACCEPTED`,
`TEST_RECONFIGURE_CLIENT_DUID_HEX`, `TEST_RECONFIGURE_CLIENT_IPV6`,
`TEST_RECONFIGURE_CLIENT_LINK_LOCAL`, `TEST_RECONFIGURE_SERVER_DUID_HEX`, and
`TEST_RECONFIGURE_REQUESTED_MESSAGE`. It must target that binding and return
success after the trigger request is accepted; the suite decides whether a
packet should appear. The suite itself extracts the 128-bit RKAP key from the
initial REPLY and validates the complete HMAC-MD5, identifiers, unicast
destination, permitted options, and monotonically increasing replay value.
If the optional external validator is supplied, it receives
`TEST_RECONFIGURE_PACKET_HEX_FILE`, pointing to the captured link-layer packet
encoded as hexadecimal, and must exit nonzero when its validation fails.

The REQUEST counter adapter runs before and after retransmission. It receives
`TEST_DHCPV6_REQUEST_TRID`, `TEST_DHCPV6_REQUEST_DUID_HEX`, and
`TEST_DHCPV6_REQUEST_PACKET_HEX`, and must print a single non-negative decimal
counter as its last nonempty output line. The suite requires the second value
to equal the first plus one while the wire reply retains the same binding.

The generation restart adapter executes twice with
`TEST_DHCPV6_GENERATION_RESTART_PHASE` set to `1` and `2`. It must return only
after the service is ready and persistent lease state is available. Configure
`TEST_DHCPV6_GENERATION_DIRECT_SUBNET`,
`TEST_DHCPV6_GENERATION_RELAY_SUBNET`,
`TEST_DHCPV6_GENERATION_RELAY_LINK_ADDRESS`, and
`TEST_DHCPV6_GENERATION_POOL_CAPACITY_PER_SUBNET` to match the target topology.
The test deliberately requires capacity to equal twice the configured sample
size, making full-pool collision and released-address reuse assertions exact.

Kea currently documents client Reconfigure as unsupported, so this profile is
not advertised by the bundled reference fixtures and remains conditional until
a target-service adapter runs it.

The supplied malformed-input, load, churn, and soak tests are intentionally
bounded, so their profile rows remain `partial`: broader per-message/per-option
fuzzing, large-pool benchmarking, and multi-hour or multi-day soak testing still
belong in a target service's deployment qualification.

## Claim boundary and RFC traceability

The maintained [RFC MUST/SHOULD traceability matrix](RFC_REQUIREMENTS.md) maps
82 acceptance-relevant normative server requirements across RFC 2131, 2132,
3011, 3046, 3396, 3442, 4361, 4702, 4704, 6842, 8925, and 9915 to exact feature
scenarios or an explicit gap. Its CSV source is
[`rfc-requirements.csv`](rfc-requirements.csv), and profile validation checks
that every evidence path and scenario name remains valid.

The matrix is deliberately honest about strength: a successful exchange is
only `partial` when it does not observe the whole normative clause, and
capability-gated requirements remain `conditional` until executed for the
target product. Open `gap`, `partial`, and unexecuted `conditional` rows mean
`GAP-RFC-TRACEABILITY` remains `partial`; the matrix makes the remaining work
enumerable rather than implying that scenario-level RFC labels are complete.

A release can accurately say that it **passes this repository's named DHCP
acceptance profile** after all applicable required, focused, lifecycle, safety,
and advertised capability checks pass. It should not say “fully RFC compliant”
until a product-specific applicability review maps every normative requirement
to a passing test or a documented exclusion.
