#!/usr/bin/env bash
# Run isolated DHCPv4 large-pool or duration-based capacity profiles.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$(uname -s)" in
  MINGW*|MSYS*)
    export MSYS2_ENV_CONV_EXCL="TEST_RESULTS_DIR${MSYS2_ENV_CONV_EXCL:+;${MSYS2_ENV_CONV_EXCL}}"
    ;;
esac

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

COMPOSE=(-f "${SCRIPT_DIR}/docker-compose.yml")
case "$SERVER" in
  isc-dhcpd)
    case "$SERVER_VERSION" in
      baseline) ;;
      isc-final)
        export ISC_DHCP_BASE_IMAGE="debian:bookworm-slim"
        ;;
      *)
        echo "[ERROR] ISC DHCP requires baseline or isc-final"
        exit 2
        ;;
    esac
    ;;
  kea)
    COMPOSE+=(-f "${SCRIPT_DIR}/docker-compose.kea.yml")
    case "$SERVER_VERSION" in
      baseline) ;;
      kea-lts)
        export KEA_BASE_IMAGE="docker.cloudsmith.io/isc/docker/kea-dhcp4:3.0.3"
        export KEA_INSTALL_MODE="alpine"
        ;;
      kea-stable)
        export KEA_BASE_IMAGE="docker.cloudsmith.io/isc/docker/kea-dhcp4:3.2.0"
        export KEA_INSTALL_MODE="alpine"
        ;;
      *)
        echo "[ERROR] Kea requires baseline, kea-lts, or kea-stable"
        exit 2
        ;;
    esac
    ;;
  *)
    echo "[ERROR] Unsupported server '$SERVER'. Use isc-dhcpd or kea."
    exit 2
    ;;
esac
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
mkdir -p "$STATE_DIR"
rm -f "$STATE_FILE" "$RESOURCE_FILE"

cleanup() {
  docker compose "${COMPOSE[@]}" down >/dev/null 2>&1 || true
  rm -f "$STATE_FILE" "$RESOURCE_FILE"
}
trap cleanup EXIT

wait_for_health() {
  local attempt
  for attempt in $(seq 1 60); do
    if [[ "$(docker inspect --format '{{.State.Health.Status}}' dhcp-test-server 2>/dev/null || true)" == "healthy" ]]; then
      return 0
    fi
    sleep 0.5
  done
  docker compose "${COMPOSE[@]}" logs --no-color dhcp-server
  echo "[ERROR] DHCP server did not become healthy"
  return 1
}

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
    docker compose "${COMPOSE[@]}" run --rm --no-deps test-runner
}

echo "[INFO] Starting capacity fixture server=${SERVER} version=${SERVER_VERSION} profile=${PROFILE} pool=${DHCPV4_POOL_START_ADDRESS}-${DHCPV4_POOL_END_ADDRESS}"
docker compose "${COMPOSE[@]}" up -d --build dhcp-server
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
