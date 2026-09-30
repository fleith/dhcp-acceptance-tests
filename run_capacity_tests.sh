#!/usr/bin/env bash
# Run isolated DHCPv4 large-pool or duration-based capacity profiles.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

SERVER="isc-dhcpd"
SERVER_VERSION="baseline"
PROFILE="smoke"
CAPTURE_TIMEOUT_OVERRIDE="${TEST_DHCPV4_CAPACITY_CAPTURE_TIMEOUT:-}"
BATCH_DEADLINE_OVERRIDE="${TEST_DHCPV4_CAPACITY_BATCH_DEADLINE:-}"

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
    --profile)
      [[ $# -ge 2 ]] || { echo "[ERROR] --profile requires a value"; exit 2; }
      PROFILE="$2"
      shift 2
      ;;
    *)
      echo "[ERROR] Unsupported argument '$1'"
      exit 2
      ;;
  esac
done

select_server_profile "$SERVER" "$SERVER_VERSION"
COMPOSE+=(-f "${SCRIPT_DIR}/docker-compose.capacity.yml")

export DHCPV4_ALT_POOL_ENABLED=0
export TEST_DHCPV4_CAPACITY_CAPTURE_TIMEOUT="${CAPTURE_TIMEOUT_OVERRIDE:-15}"
export TEST_DHCPV4_CAPACITY_BATCH_DEADLINE="${BATCH_DEADLINE_OVERRIDE:-30}"
export TEST_DHCPV4_CAPACITY_P95_LIMIT_MS="${TEST_DHCPV4_CAPACITY_P95_LIMIT_MS:-5000}"
export TEST_DHCPV4_CAPACITY_MIN_COMMITS_PER_SECOND="${TEST_DHCPV4_CAPACITY_MIN_COMMITS_PER_SECOND:-1}"
export TEST_DHCPV4_CAPACITY_RELEASE_SETTLE_SECONDS="${TEST_DHCPV4_CAPACITY_RELEASE_SETTLE_SECONDS:-0.5}"
export TEST_DHCPV4_CAPACITY_MEMORY_GROWTH_LIMIT_MIB="${TEST_DHCPV4_CAPACITY_MEMORY_GROWTH_LIMIT_MIB:-256}"
export TEST_DHCPV4_CAPACITY_MEMORY_PER_LEASE_LIMIT_KIB="${TEST_DHCPV4_CAPACITY_MEMORY_PER_LEASE_LIMIT_KIB:-512}"
export TEST_DHCPV4_CAPACITY_PIDS_GROWTH_LIMIT="${TEST_DHCPV4_CAPACITY_PIDS_GROWTH_LIMIT:-8}"

case "$PROFILE" in
  smoke)
    PHASE="capacity_scale"
    export DHCPV4_POOL_START_ADDRESS="172.29.1.10"
    export DHCPV4_POOL_END_ADDRESS="172.29.2.9"
    export TEST_DHCPV4_CAPACITY_POOL_SIZE=256
    export TEST_DHCPV4_CAPACITY_BATCH_SIZE=64
    export TEST_DHCPV4_CAPACITY_REPLACEMENTS=64
    export TEST_DHCPV4_CAPACITY_POST_BATCH_SIZE=16
    ;;
  scheduled)
    PHASE="capacity_scale"
    export DHCPV4_POOL_START_ADDRESS="172.29.1.10"
    export DHCPV4_POOL_END_ADDRESS="172.29.5.9"
    export TEST_DHCPV4_CAPACITY_POOL_SIZE=1024
    export TEST_DHCPV4_CAPACITY_BATCH_SIZE=96
    export TEST_DHCPV4_CAPACITY_REPLACEMENTS=192
    export TEST_DHCPV4_CAPACITY_POST_BATCH_SIZE=32
    export TEST_DHCPV4_CAPACITY_CAPTURE_TIMEOUT="${CAPTURE_TIMEOUT_OVERRIDE:-30}"
    export TEST_DHCPV4_CAPACITY_BATCH_DEADLINE="${BATCH_DEADLINE_OVERRIDE:-60}"
    ;;
  endurance)
    PHASE="capacity_endurance"
    export DHCPV4_POOL_START_ADDRESS="172.29.1.10"
    export DHCPV4_POOL_END_ADDRESS="172.29.3.9"
    export TEST_DHCPV4_CAPACITY_POOL_SIZE=512
    export TEST_DHCPV4_CAPACITY_BATCH_SIZE="${TEST_DHCPV4_CAPACITY_BATCH_SIZE:-64}"
    export TEST_DHCPV4_CAPACITY_REPLACEMENTS="${TEST_DHCPV4_CAPACITY_REPLACEMENTS:-64}"
    export TEST_DHCPV4_CAPACITY_POST_BATCH_SIZE="${TEST_DHCPV4_CAPACITY_POST_BATCH_SIZE:-16}"
    export TEST_DHCPV4_CAPACITY_DURATION_SECONDS="${TEST_DHCPV4_CAPACITY_DURATION_SECONDS:-3600}"
    export TEST_DHCPV4_CAPACITY_MIN_ENDURANCE_COMMITS="${TEST_DHCPV4_CAPACITY_MIN_ENDURANCE_COMMITS:-1024}"
    ;;
  *)
    echo "[ERROR] Unsupported profile '$PROFILE'. Use smoke, scheduled, or endurance."
    exit 2
    ;;
esac

STATE_DIR="${SCRIPT_DIR}/test-state"
STATE_FILE="${STATE_DIR}/dhcpv4-capacity-state.json"
RESOURCE_FILE="${STATE_DIR}/dhcpv4-capacity-resources.ndjson"
ensure_host_dirs
rm -f "$STATE_FILE" "$RESOURCE_FILE"

cleanup() {
  compose_down
  rm -f "$STATE_FILE" "$RESOURCE_FILE"
}
trap cleanup EXIT

capture_resource_sample() {
  local sample
  sample="$(docker stats --no-stream --format '{{json .}}' dhcp-test-server)"
  [[ -n "$sample" ]] || { echo "[ERROR] Docker returned an empty resource sample"; return 1; }
  printf '%s\n' "$sample" >> "$RESOURCE_FILE"
}

run_phase() {
  local phase="$1"
  local suffix="$2"
  TEST_BEHAVE_ARGS="--tags=@orchestrated --tags=@${phase} --no-skipped" \
  TEST_REQUIRE_EXECUTED_SCENARIOS=1 \
  TEST_RESULTS_DIR="/app/test-results/capacity-${SERVER}-${SERVER_VERSION}-${PROFILE}-${suffix}" \
    docker compose "${COMPOSE[@]}" run --rm --no-deps test-runner < /dev/null
}

echo "[INFO] Starting capacity fixture server=${SERVER} version=${SERVER_VERSION} profile=${PROFILE} pool=${DHCPV4_POOL_START_ADDRESS}-${DHCPV4_POOL_END_ADDRESS}"
docker compose "${COMPOSE[@]}" build dhcp-server test-runner
docker compose "${COMPOSE[@]}" up -d dhcp-server
wait_for_health

capture_resource_sample
run_phase "$PHASE" run &
capacity_pid=$!
while kill -0 "$capacity_pid" 2>/dev/null; do
  capture_resource_sample
  sleep 1
done
wait "$capacity_pid"
capture_resource_sample

run_phase capacity_verify verify

echo "[INFO] DHCPv4 capacity profile passed for ${SERVER}/${SERVER_VERSION}/${PROFILE}"
