#!/usr/bin/env bash
# Verify runtime lease selection for a backend that accepts overlapping subnets.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
SERVER="kea"
SERVER_VERSION="kea-stable"

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

if [[ "$SERVER" != "kea" ]]; then
  echo "[ERROR] Runtime overlap leases require a fixture that accepts overlap; ISC DHCP rejects this topology"
  exit 2
fi

case "$SERVER_VERSION" in
  baseline|kea-lts|kea-stable) ;;
  *)
    echo "[ERROR] Unsupported Kea version '$SERVER_VERSION'"
    exit 2
    ;;
esac

run_phase() {
  local order="$1"
  local scope="$2"
  local pool_start="$3"
  local pool_end="$4"
  local losing_hint="$5"
  local domain="$6"

  echo "[INFO] Overlap lease phase order=${order} expected_scope=${scope} version=${SERVER_VERSION}"
  DHCPV4_INJECT_OVERLAPPING_SUBNET=1 \
  DHCPV4_OVERLAP_ORDER="$order" \
  DHCPV4_POOL_START_OFFSET=160 \
  DHCPV4_POOL_END_OFFSET=170 \
  DHCPV4_ALT_POOL_ENABLED=0 \
  TEST_DHCPV4_OVERLAP_EXPECTED_POOL_START="$pool_start" \
  TEST_DHCPV4_OVERLAP_EXPECTED_POOL_END="$pool_end" \
  TEST_DHCPV4_OVERLAP_LOSING_HINT="$losing_hint" \
  TEST_DHCPV4_OVERLAP_EXPECTED_DOMAIN="$domain" \
  TEST_DHCPV4_OVERLAP_EXPECTED_SCOPE="$scope" \
  TEST_CAPABILITIES=overlap_leases \
  TEST_REQUIRE_EXECUTED_SCENARIOS=1 \
  TEST_RESULTS_RUN_SUFFIX="overlap-${order}" \
    bash "${SCRIPT_DIR}/run_dhcp_tests.sh" \
      --server "$SERVER" \
      --server-version "$SERVER_VERSION" \
      --ip-version v4 \
      --tags @requires_overlap_leases \
      --tags @overlap_lease_behavior
}

# Reordering the accepted subnets must not silently change the reference
# selection result.  Both profiles therefore expect the primary scope while
# still proving that a hint from the nested /25 cannot override that result.
run_phase primary-first primary 172.29.0.160 172.29.0.170 172.29.0.10 overlap-primary.test
run_phase specific-first primary 172.29.0.160 172.29.0.170 172.29.0.10 overlap-primary.test

echo "[INFO] Overlapping-subnet lease scenarios passed for ${SERVER}/${SERVER_VERSION}"
