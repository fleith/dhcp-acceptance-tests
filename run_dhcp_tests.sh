#!/usr/bin/env bash
# Run the DHCP acceptance tests against a server launched in Docker.
#
# This script is intended for local development.  It starts the ISC DHCP
# server container using docker compose, runs the Behave tests, and
# then shuts the server down.  You can override the test environment
# variables by exporting them before running this script.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"

echo "[INFO] Starting DHCP server via docker compose…"
docker compose -f "${PROJECT_ROOT}/docker-compose.yml" up -d dhcp-server

echo "[INFO] Waiting for server to initialize…"
sleep 5

echo "[INFO] Running Behave tests…"
cd "${PROJECT_ROOT}"
# Set default values if not already exported.  These should match
# dhcp/data/dhcpd.conf.
export TEST_SERVER_IP="${TEST_SERVER_IP:-192.168.56.1}"
export TEST_INTERFACE="${TEST_INTERFACE:-eth0}"
export TEST_SUBNET="${TEST_SUBNET:-192.168.56.0/24}"
export TEST_LEASE_TIME="${TEST_LEASE_TIME:-120}"
/home/alvaro/dhcp_acceptance_tests/dhcp_acceptance_tests/.venv/bin/behave -f progress

echo "[INFO] Stopping DHCP server…"
docker compose -f "${PROJECT_ROOT}/docker-compose.yml" down

echo "[INFO] Tests complete."
