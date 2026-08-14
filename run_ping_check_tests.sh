#!/usr/bin/env bash
# Run RFC 2131 server-side candidate address ping-check scenarios in isolation.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
SERVER="isc-dhcpd"
SERVER_VERSION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      [[ $# -ge 2 ]] || { echo "[ERROR] --server requires a value"; exit 2; }
      SERVER="$2"
      shift 2
      ;;
    --server-version)
      [[ $# -ge 2 ]] || { echo "[ERROR] --server-version requires a value"; exit 2; }
      SERVER_VERSION="$2"
      shift 2
      ;;
    *)
      echo "[ERROR] Unsupported argument '$1'"
      exit 2
      ;;
  esac
done

case "$SERVER" in
  isc-dhcpd)
    SERVER_VERSION="${SERVER_VERSION:-baseline}"
    ;;
  kea)
    SERVER_VERSION="${SERVER_VERSION:-kea-stable}"
    if [[ "$SERVER_VERSION" == "baseline" ]]; then
      echo "[ERROR] The Kea 2.2 baseline does not contain libdhcp_ping_check.so; use kea-lts or kea-stable"
      exit 2
    fi
    ;;
  *)
    echo "[ERROR] Unsupported server '$SERVER'. Use isc-dhcpd or kea."
    exit 2
    ;;
esac

run_phase() {
  local phase="$1"
  local offset="$2"
  echo "[INFO] RFC 2131 ping-check phase=${phase} server=${SERVER} version=${SERVER_VERSION}"
  DHCPV4_PING_CHECK_ENABLED=1 \
  DHCPV4_PING_TIMEOUT=1 \
  DHCPV4_PING_TIMEOUT_MS=300 \
  DHCPV4_POOL_START_OFFSET="$offset" \
  DHCPV4_POOL_END_OFFSET="$offset" \
  DHCPV4_ALT_POOL_ENABLED=0 \
  TEST_DHCPV4_PING_CHECK_ADDRESS="172.29.0.${offset}" \
  TEST_CAPABILITIES=server_ping_check \
  TEST_REQUIRE_EXECUTED_SCENARIOS=1 \
  TEST_RESULTS_RUN_SUFFIX="ping-check-${phase}" \
    bash "${SCRIPT_DIR}/run_dhcp_tests.sh" \
      --server "$SERVER" \
      --server-version "$SERVER_VERSION" \
      --ip-version v4 \
      --tags "@requires_server_ping_check" \
      --tags "@ping_check_${phase}"
}

# Separate fixtures and addresses avoid carrying a prior OFFER or DECLINED
# state into the opposite assertion.
run_phase silent 198
run_phase occupied 199

echo "[INFO] RFC 2131 server ping-check scenarios passed for ${SERVER}/${SERVER_VERSION}"
