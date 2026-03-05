# DHCP Acceptance Tests

This project contains behavior‑driven acceptance tests for a DHCP server.  It uses the [Behave](https://behave.readthedocs.io/) BDD framework for Python and [Scapy](https://scapy.net/) to craft and inspect DHCP packets.

## Why Python + Behave?

- **BDD support:** Behave implements the Gherkin language (Given/When/Then), making it easy to express DHCP scenarios as executable requirements.
- **Rich networking libraries:** Python has libraries like Scapy to send and analyse DHCP messages; there is no equivalent built‑in support in some other BDD frameworks.
- **Cross‑platform:** Tests can run on Linux/Mac/Windows and integrate with CI/CD pipelines.

## Installing

Create a virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

> **Note:** You may need root privileges or to run in a container network namespace to send raw DHCP packets.  Alternatively, you can abstract the network logic and mock responses.

## Running the tests

From the project root:

```bash
behave
```

This will execute all scenarios in the `features/` directory.

### Running against a real DHCP server

By default the tests assume a server on the host network (IP address
``192.168.56.1``) and send packets on interface ``eth0``.  You can
override these by exporting environment variables before running
``behave``:

```bash
export TEST_SERVER_IP=192.168.56.10
export TEST_INTERFACE=docker0
export TEST_SUBNET=192.168.56.0/24
behave
```

### Starting a DHCP server with Docker

This repository includes a ``docker-compose.yml`` that defines a
service running the ISC DHCP server (via the ``networkboot/dhcpd``
image).  To run the tests against this container on a Linux host:

```bash
# build and launch the dhcp server in the background
docker compose up -d dhcp-server

# wait a few seconds for dhcpd to start
sleep 5

# run the tests on your machine (not in Docker) with variables set to
# reach the container.  The server image binds to the host network,
# so use the host’s interface name and subnet (see docker-compose.yml).
TEST_SERVER_IP=192.168.56.1 TEST_INTERFACE=eth0 TEST_SUBNET=192.168.56.0/24 behave

# shut down the server when done
docker compose down
```

GitHub Actions can use the same ``docker-compose.yml`` via the
provided workflow at ``.github/workflows/ci.yml``.

## Project structure

```
dhcp_acceptance_tests/
├── features/
│   ├── dhcp_lease.feature
│   ├── dhcp_renewal.feature
│   └── steps/
│       └── dhcp_steps.py
├── requirements.txt
└── README.md
```

- `dhcp_lease.feature` – Gherkin scenarios for obtaining and releasing leases.
- `dhcp_renewal.feature` – Scenarios for lease renewal and expiry.
- `steps/dhcp_steps.py` – Python step definitions that implement the Gherkin steps.  They use Scapy to send DHCP DISCOVER/REQUEST packets and verify responses from the server.  The code includes placeholders for your specific server address, subnet and interface.

## Next steps

- Expand the scenarios to cover negative cases (invalid messages, out‑of‑scope requests, MAC filtering).
- Parameterize subnet and lease duration via Behave contexts or environment variables.
- Integrate with your CI/CD pipeline to run these tests automatically when the DHCP server is updated.
