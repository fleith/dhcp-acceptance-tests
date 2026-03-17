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
bash ./run_dhcp_tests.sh [--server isc-dhcpd|kea] [--ip-version v4|v6|dual]
```

Examples:

```bash
# Default: ISC DHCPv4
bash ./run_dhcp_tests.sh

# Kea DHCPv4
bash ./run_dhcp_tests.sh --server kea

# ISC DHCPv6
bash ./run_dhcp_tests.sh --ip-version v6

# Run both v4 and v6 for one server
bash ./run_dhcp_tests.sh --server isc-dhcpd --ip-version dual
```

The script composes the correct Docker files and always tears down the stack after each run.

Note: `--server kea --ip-version v6` is currently unsupported in this topology due a Kea DHCPv6 socket bind limitation on Docker bridge networking.

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
| `TEST_INTERFACE` | `eth0` | Interface used for raw packets |
| `TEST_SUBNET` | detected from interface | Expected DHCPv4 lease subnet |
| `TEST_SUBNET_V6` | detected from interface | Expected DHCPv6 lease subnet |
| `TEST_LEASE_TIME` | `120` | Lease duration in seconds |
| `TEST_CLIENT_MAC` | `02:00:00:00:00:01` | Fallback DHCPv4 client MAC |

## Coverage snapshot

Current suite covers key behaviors from:

- **RFC 2131**: DORA flow, release, renew, rebinding edge cases, INIT-REBOOT, INFORM, NAK/DECLINE handling.
- **RFC 2132**: required network options and T1/T2 lease timer validation.
- **RFC 3046**: relay-agent-information (Option 82) request acceptance path.
- **RFC 3396**: concatenated option fragment acceptance path.
- **RFC 6842**: client-identifier based lease stability across different hardware addresses.
- **RFC 8415**: DHCPv6 SOLICIT/ADVERTISE/REQUEST/REPLY and RENEW acceptance paths.

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
|   |-- dhcp_rfc3046_relay_agent.feature
|   |-- dhcp_rfc3396_option_concat.feature
|   |-- dhcp_rfc6842_client_identifier.feature
|   |-- dhcpv6_lease.feature
|   |-- environment.py
|   `-- steps/
|       |-- dhcp_steps.py
|       `-- dhcpv6_steps.py
|-- docker-compose.yml
|-- docker-compose.kea.yml
|-- docker-compose.ipv6.yml
|-- run_dhcp_tests.sh
|-- run_tests.py
|-- .github/workflows/ci.yml
`-- requirements.txt
```

## CI

GitHub Actions runs the supported matrix:

- `isc-dhcpd` with `v4` and `v6`
- `kea` with `v4`

Kea DHCPv6 is currently excluded due a Docker bridge link-local socket limitation.
