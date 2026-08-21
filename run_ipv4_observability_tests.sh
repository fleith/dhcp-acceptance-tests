#!/usr/bin/env bash
# Run the isolated IPv4 log, addressless-allocation, and DDNS profiles.

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
    SERVER_VERSION="${SERVER_VERSION:-isc-final}"
    SERVER_LOG_PATH=/test-state/dhcpv4-server.log
    ;;
  kea)
    SERVER_VERSION="${SERVER_VERSION:-kea-stable}"
    SERVER_LOG_PATH=/var/log/kea/dhcpv4-server.log
    [[ "$SERVER_VERSION" != "baseline" ]] || {
      echo "[ERROR] RFC 8925 addressless observation requires Kea 3.x"
      exit 2
    }
    ;;
  *)
    echo "[ERROR] Unsupported server '$SERVER'"
    exit 2
    ;;
esac

mkdir -p "${SCRIPT_DIR}/test-state"
rm -f "${SCRIPT_DIR}/test-state/dhcpv4-server.log"

echo "[INFO] Observing DHCPDECLINE notification for ${SERVER}/${SERVER_VERSION}"
DHCPV4_SERVER_LOG_FILE="$SERVER_LOG_PATH" \
TEST_DHCPV4_SERVER_LOG_FILE=/app/test-state/dhcpv4-server.log \
TEST_CAPABILITIES=admin_notification \
TEST_REQUIRE_EXECUTED_SCENARIOS=1 \
TEST_RESULTS_RUN_SUFFIX=admin-notification \
  bash "${SCRIPT_DIR}/run_dhcp_tests.sh" \
    --server "$SERVER" \
    --server-version "$SERVER_VERSION" \
    --ip-version v4 \
    --tags @requires_admin_notification

if [[ "$SERVER" == "kea" ]]; then
  echo "[INFO] Observing RFC 8925 addressless allocation behavior"
  DHCPV4_POOL_START_OFFSET=196 \
  DHCPV4_POOL_END_OFFSET=197 \
  DHCPV4_ALT_POOL_ENABLED=0 \
  TEST_CAPABILITIES=rfc8925_addressless_observability \
  TEST_REQUIRE_EXECUTED_SCENARIOS=1 \
  TEST_RESULTS_RUN_SUFFIX=rfc8925-addressless \
    bash "${SCRIPT_DIR}/run_dhcp_tests.sh" \
      --server "$SERVER" \
      --server-version "$SERVER_VERSION" \
      --ip-version v4 \
      --tags @requires_rfc8925_addressless_observability
fi

if [[ "$SERVER" == "isc-dhcpd" ]]; then
  echo "[INFO] Observing live RFC 4702 DNS update timing and name precedence"
  TEST_REQUIRE_EXECUTED_SCENARIOS=1 \
  TEST_RESULTS_RUN_SUFFIX=ddns \
    bash "${SCRIPT_DIR}/run_dhcp_tests.sh" \
      --server "$SERVER" \
      --server-version "$SERVER_VERSION" \
      --ip-version v4 \
      --compose-file "${SCRIPT_DIR}/docker-compose.ddns.yml" \
      --tags @requires_ddns
fi

echo "[INFO] IPv4 observability profiles passed for ${SERVER}/${SERVER_VERSION}"
