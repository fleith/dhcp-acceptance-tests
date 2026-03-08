# DHCP Acceptance Tests

[![DHCP Acceptance Tests](https://github.com/fleith/dhcp-acceptance-tests/actions/workflows/ci.yml/badge.svg)](https://github.com/fleith/dhcp-acceptance-tests/actions/workflows/ci.yml)

Behavior-driven acceptance tests for a DHCP server using [Behave](https://behave.readthedocs.io/) and [Scapy](https://scapy.net/).

## Why Python + Behave?

- **BDD support:** Gherkin (Given/When/Then) makes DHCP scenarios read as executable requirements.
- **Rich networking libraries:** Scapy provides full control over DHCP packet construction and capture.
- **CI-friendly:** Runs entirely in Docker, no host configuration required.

## Running the tests

The recommended way is Docker Compose - it starts the DHCP server and test runner together, with no manual configuration needed:

```bash
docker compose up --abort-on-container-exit --exit-code-from test-runner
```

Docker Compose uses an isolated bridge network (`dhcp-test-net`) with static container IPs and a DHCP server health check before tests start:

- DHCP server: `172.29.0.2`
- Test runner: `172.29.0.3`
- Interface inside both containers: `eth0`

The test runner auto-detects subnet details from `TEST_INTERFACE` and uses `TEST_SERVER_IP` from the environment.

### Running tests natively (advanced)

If you want to run tests directly on the host against an already-running DHCP server:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Requires root for raw packet I/O
TEST_SERVER_IP=<server-ip> TEST_SUBNET=<cidr> TEST_INTERFACE=<iface> sudo -E .venv/bin/python3 -m behave
```

| Variable | Default | Description |
|---|---|---|
| `TEST_SERVER_IP` | `192.168.56.1` | IP address of the DHCP server |
| `TEST_INTERFACE` | `eth0` | Network interface for raw packets |
| `TEST_SUBNET` | `192.168.56.0/24` | Expected lease subnet (for validation) |
| `TEST_LEASE_TIME` | `120` | Lease duration in seconds |
| `TEST_CLIENT_MAC` | `02:00:00:00:00:01` | Test client MAC address |

## Coverage snapshot

Current suite covers key behaviors from:

- **RFC 2131**: DORA flow, release, renew, rebinding edge cases, INIT-REBOOT, INFORM, NAK/DECLINE handling.
- **RFC 2132**: required network options and T1/T2 lease timer validation.
- **RFC 3046**: relay-agent-information (Option 82) request acceptance path.
- **RFC 3396**: concatenated option fragment acceptance path.
- **RFC 6842**: client-identifier based lease stability across different hardware addresses.

## Project structure

```
dhcp-acceptance-tests/
|-- dhcp/
|   |-- Dockerfile                        # Custom dhcpd image with auto-detection entrypoint
|   `-- entrypoint.sh                     # Detects eth0 subnet, generates dhcpd.conf, starts dhcpd
|-- features/
|   |-- dhcp_lease.feature                # Lease obtain/release
|   |-- dhcp_renewal.feature              # Renew, expiry, rebinding edge cases
|   |-- dhcp_options.feature              # DHCP options + T1/T2 validation
|   |-- dhcp_nak_decline.feature          # DHCPNAK + DHCPDECLINE behavior
|   |-- dhcp_init_reboot.feature          # INIT-REBOOT behavior
|   |-- dhcp_inform.feature               # DHCPINFORM behavior
|   |-- dhcp_address_pool.feature         # Address pool/reconnect behavior
|   |-- dhcp_rfc3046_relay_agent.feature  # RFC 3046 Option 82 coverage
|   |-- dhcp_rfc3396_option_concat.feature# RFC 3396 option concatenation coverage
|   |-- dhcp_rfc6842_client_identifier.feature # RFC 6842 client-identifier coverage
|   |-- environment.py                    # Behave hooks for scenario isolation/cleanup
|   `-- steps/
|       `-- dhcp_steps.py                 # Scapy-based step definitions
|-- .github/workflows/ci.yml              # GitHub Actions CI
|-- docker-compose.yml                    # Runs dhcp-server + test-runner containers
|-- run_tests.py                          # Detects network config and invokes behave
`-- requirements.txt
```

## CI

GitHub Actions runs the full suite on every push and pull request to `master` using the same `docker compose` command as local development. See [Actions](https://github.com/fleith/dhcp-acceptance-tests/actions).

## Next steps

- Expand negative/robustness scenarios: malformed packets, invalid option lengths, and invalid state transitions.
- Add relay-agent topology tests with a real relay path (not only direct-attach Option 82 injection).
