#!/usr/bin/env bash
# Exercise persistent DHCPv4 bindings across graceful and abrupt restarts.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
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

COMPOSE=(-f "${SCRIPT_DIR}/docker-compose.yml")
case "$SERVER" in
  isc-dhcpd)
    ;;
  kea)
    COMPOSE+=(-f "${SCRIPT_DIR}/docker-compose.kea.yml")
    ;;
  *)
    echo "[ERROR] Unsupported server '$SERVER'. Use isc-dhcpd or kea."
    exit 2
    ;;
esac

export DHCPV4_POOL_START_OFFSET=190
export DHCPV4_POOL_END_OFFSET=191
export DHCPV4_ALT_POOL_ENABLED=0

cleanup() {
  docker compose "${COMPOSE[@]}" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_health() {
  local attempt
  for attempt in $(seq 1 40); do
    if [[ "$(docker inspect --format '{{.State.Health.Status}}' dhcp-test-server 2>/dev/null || true)" == "healthy" ]]; then
      return 0
    fi
    sleep 0.5
  done
  docker compose "${COMPOSE[@]}" logs --no-color dhcp-server
  echo "[ERROR] DHCP server did not become healthy"
  return 1
}

run_phase() {
  local phase="$1"
  local suffix="$2"
  local expected_domain="${3:-class.acceptance.test}"
  docker compose "${COMPOSE[@]}" run --rm --no-deps \
    -e TEST_BEHAVE_ARGS="--tags=@${phase}" \
    -e TEST_RESULTS_DIR="/app/test-results/lifecycle-${SERVER}-${suffix}" \
    -e TEST_DHCPV4_CLASS_DOMAIN="$expected_domain" \
    test-runner
}

echo "[INFO] Starting persistent lifecycle fixture for server=${SERVER}"
docker compose "${COMPOSE[@]}" up -d --build dhcp-server
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
