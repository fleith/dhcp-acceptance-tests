#!/usr/bin/env bash
# Exercise persistent DHCPv4 bindings across graceful and abrupt restarts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"
SERVER="isc-dhcpd"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      [[ $# -ge 2 ]] || { echo "[ERROR] --server requires a value"; exit 2; }
      SERVER="$2"
      shift 2
      ;;
    *)
      echo "[ERROR] Unsupported argument '$1'"
      exit 2
      ;;
  esac
done

select_server_profile "$SERVER" baseline

export DHCPV4_POOL_START_OFFSET=190
export DHCPV4_POOL_END_OFFSET=191
export DHCPV4_ALT_POOL_ENABLED=0

cleanup() {
  compose_down
}
trap cleanup EXIT

run_phase() {
  local phase="$1"
  local suffix="$2"
  local expected_domain="${3:-class.acceptance.test}"
  docker compose "${COMPOSE[@]}" run --rm --no-deps \
    -e TEST_BEHAVE_ARGS="--tags=@${phase}" \
    -e TEST_RESULTS_DIR="/app/test-results/lifecycle-${SERVER}-${suffix}" \
    -e TEST_DHCPV4_CLASS_DOMAIN="$expected_domain" \
    test-runner < /dev/null
}

ensure_host_dirs

echo "[INFO] Starting persistent lifecycle fixture for server=${SERVER}"
docker compose "${COMPOSE[@]}" build dhcp-server test-runner
docker compose "${COMPOSE[@]}" up -d dhcp-server
wait_for_health
run_phase persistence_prepare prepare

echo "[INFO] Verifying graceful restart recovery"
docker compose "${COMPOSE[@]}" restart dhcp-server
wait_for_health
run_phase persistence_verify graceful

echo "[INFO] Verifying SIGKILL crash recovery"
docker compose "${COMPOSE[@]}" kill -s SIGKILL dhcp-server
docker compose "${COMPOSE[@]}" start dhcp-server
wait_for_health
run_phase persistence_verify crash

run_phase persistence_cleanup cleanup
echo "[INFO] Persistent lifecycle fixture passed for server=${SERVER}"
