# DHCP Acceptance Tests

[![DHCP Acceptance Tests](https://github.com/fleith/dhcp-acceptance-tests/actions/workflows/ci.yml/badge.svg)](https://github.com/fleith/dhcp-acceptance-tests/actions/workflows/ci.yml)

Behavior-driven acceptance tests for a DHCP server using [Behave](https://behave.readthedocs.io/) and [Scapy](https://scapy.net/).

## Why Python + Behave?

- **BDD support:** Gherkin (Given/When/Then) makes DHCP scenarios read as executable requirements.
- **Rich networking libraries:** Scapy provides full control over DHCP packet construction and capture.
- **CI-friendly:** Runs entirely in Docker, no host configuration required.

## Running the tests

The recommended way is Docker Compose — it starts the DHCP server and test runner together, with no manual configuration needed:

```bash
docker compose up --abort-on-container-exit --exit-code-from test-runner
```

Both containers use `network_mode: host` so DHCP broadcasts reach the server. The server and test runner auto-detect the network interface at startup, so this works on any Linux host.

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
| `TEST_LEASE_TIME` | `60` | Lease duration in seconds |
| `TEST_CLIENT_MAC` | `02:00:00:00:00:01` | Test client MAC address |

## Project structure

```
dhcp-acceptance-tests/
├── dhcp/
│   ├── Dockerfile        # Custom dhcpd image with auto-detection entrypoint
│   └── entrypoint.sh     # Detects eth0 subnet, generates dhcpd.conf, starts dhcpd
├── features/
│   ├── dhcp_lease.feature    # Scenarios: obtain lease, release lease
│   ├── dhcp_renewal.feature  # Scenarios: renew lease, lease expiry
│   └── steps/
│       └── dhcp_steps.py     # Scapy-based step definitions
├── .github/workflows/ci.yml  # GitHub Actions CI
├── docker-compose.yml        # Runs dhcp-server + test-runner containers
├── run_tests.py              # Detects network config and invokes behave
└── requirements.txt
```

## CI

GitHub Actions runs the full suite on every push and pull request to `master` using the same `docker compose` command as local development. See [Actions](https://github.com/fleith/dhcp-acceptance-tests/actions).

## Next steps

- Add negative scenarios: invalid messages, out-of-scope requests, MAC filtering.
- Add a health check to `docker-compose.yml` so the test runner waits for dhcpd to be ready instead of sleeping.
