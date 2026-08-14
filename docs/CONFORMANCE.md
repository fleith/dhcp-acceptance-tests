# DHCP service qualification profile

This repository tests concrete DHCP behaviors. It does not issue a blanket
standards-compliance certificate. A service may claim the rows it has executed
successfully, using the exact server version and configuration recorded with
the results.

The machine-readable coverage index is
[`conformance-profile.json`](conformance-profile.json). `covered` means that a
test is supplied and runs against the reference ISC DHCP and Kea fixtures.
`conditional` means that the test is supplied but requires a service-specific
adapter or topology. `partial` means that more requirements analysis is still
needed before making a complete claim.

## Test levels

| Level | Invocation | Purpose |
|---|---|---|
| Required | `bash ./run_dhcp_tests.sh --server <server> --ip-version <version>` | Protocol flows and ordinary negative cases |
| Focused robustness | `bash ./run_dhcp_tests.sh --server <server> --ip-version v4 --tags @focused_robustness` | Bounded malformed corpus, concurrent load deadline, and churn |
| Pool exhaustion | Select `@pool_exhaustion` with a deliberately small pool | Exhaustion and recovery without making normal runs consume the entire pool |
| Server ping check | `bash ./run_ping_check_tests.sh --server <server>` | RFC 2131 candidate-address ICMP probing with silent and responding peers |
| Overlapping leases | `bash ./run_overlap_lease_tests.sh --server kea` | Runtime pool and option selection in both accepted subnet declaration orders |
| Lifecycle | `bash ./run_lifecycle_tests.sh --server <server>` | Graceful restart, SIGKILL recovery, and persistent binding ownership |
| Configuration safety | `bash ./run_config_safety_tests.sh --server <server> [--overlap-policy reject\|allow]` | Explicit overlap policy and unavailable lease-store rejection |
| Capability | Select `@capability` or one `@requires_*` tag and configure its adapter | Product features that cannot be assumed for every DHCP server |

The focused checks are deliberately bounded. They catch correctness and basic
resource regressions; they are not a capacity benchmark, soak test, or a
substitute for product-specific sizing.

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

## Capability adapters

Capabilities are skipped unless their name is present in the comma-separated
`TEST_CAPABILITIES` value. This prevents an absent optional feature from being
reported as a pass.

| Capability | Required configuration |
|---|---|
| `reload` | `TEST_RELOAD_COMMAND`; optionally `TEST_RELOADED_CLASS_DOMAIN` |
| `ha` | `TEST_HA_FAILOVER_COMMAND`; optionally `TEST_HA_RECOVER_COMMAND` |
| `ddns` | `TEST_DNS_SERVER` and `TEST_DDNS_FQDN` |
| `multi_interface` | `TEST_SECOND_INTERFACE`, `TEST_SECOND_SUBNET`, and `TEST_SECOND_SERVER_IP` |
| `authenticated_reconfigure` | `TEST_RECONFIGURE_TRIGGER_COMMAND` and `TEST_RECONFIGURE_AUTH_VALIDATOR_COMMAND` |
| `storage_fault` | `TEST_STORAGE_FAIL_COMMAND` and `TEST_STORAGE_RECOVER_COMMAND` |

Adapter commands execute inside the test-runner container. The authenticated
Reconfigure validator receives `TEST_RECONFIGURE_PACKET_HEX_FILE`, pointing to
the captured packet encoded as hexadecimal, and must exit non-zero if
cryptographic authentication is invalid.

The supplied malformed-input, load, and churn tests are intentionally bounded,
so their profile rows remain `partial`: broader per-message/per-option fuzzing,
large-pool benchmarking, and long-duration soak testing still belong in a
target service's deployment qualification.

## Claim boundary and RFC traceability

The feature files give scenario-level traceability for RFC 2131, 2132, 3011,
3046, 3396, 3442, 4361, 4702, 4704, 6842, 8925, and 9915. They do not yet form
an exhaustive paragraph-by-paragraph inventory of every applicable normative
MUST and SHOULD in those RFCs. `GAP-RFC-TRACEABILITY` therefore remains
`partial` in the profile.

A release can accurately say that it **passes this repository's named DHCP
acceptance profile** after all applicable required, focused, lifecycle, safety,
and advertised capability checks pass. It should not say “fully RFC compliant”
until a product-specific applicability review maps every normative requirement
to a passing test or a documented exclusion.
