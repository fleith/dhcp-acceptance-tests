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
  [--server-version baseline|isc-final|kea-lts|kea-stable] [--tags TAG_EXPRESSION]
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
```

The script composes the correct Docker files and always tears down the stack after each run.

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

## Coverage snapshot

Server-focused coverage spans 12 RFCs: the existing eight plus RFC 3442,
RFC 4361, RFC 4704, and RFC 8925.

- **RFC 2131**: DORA flow, release, renew, rebinding edge cases, INIT-REBOOT, INFORM, NAK/DECLINE handling.
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
- **RFC 9915**: DHCPv6 lease acquisition, lifetime validation, RENEW, REBIND, RELEASE, DECLINE, stateless INFORMATION-REQUEST, IA_PD prefix delegation, CONFIRM status handling, relay-forward/relay-reply address assignment, Reconfigure-Accept signaling, and malformed or unauthorized message recovery. Authenticated server-initiated Reconfigure remains outside the fixture's claims. IA_PD and these lifecycle paths deepen existing RFC coverage rather than adding another RFC to the count.

Additional coverage is intentionally excluded from the 12-RFC server count:

- **RFC 5227**: client-companion IPv4 Address Conflict Detection, including conflict, no-conflict, and DHCPDECLINE paths; this is not DHCP server compliance coverage.
- **RFC 4039**: unsupported DHCPv4 Rapid Commit fallback and malformed-option recovery, tagged as non-compliance coverage; neither backend claims RFC 4039 support.

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
|   |-- environment.py
|   `-- steps/
|       |-- dhcp_steps.py
|       |-- dhcpv4_support.py
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
warning; unclassified compatibility failures still fail their job.

Every matrix row writes a Markdown summary and uploads its JUnit reports for 14
days, including failed runs. The full workflow also runs every Monday and can
be started manually from GitHub.
