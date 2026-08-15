#!/usr/bin/env bash
# Run bounded DHCPv4 lease churn while sampling server resource usage.

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

export DHCPV4_POOL_START_OFFSET=100
export DHCPV4_POOL_END_OFFSET=200
export DHCPV4_ALT_POOL_ENABLED=0
export TEST_DHCPV4_SOAK_POOL_CAPACITY=101

case "$PROFILE" in
  smoke)
    export TEST_DHCPV4_SOAK_ROUNDS=8
    export TEST_DHCPV4_SOAK_BATCH_SIZE=16
    export TEST_DHCPV4_SOAK_POST_BATCH_SIZE=8
    export TEST_DHCPV4_SOAK_CAPTURE_TIMEOUT=10
    export TEST_DHCPV4_SOAK_BATCH_DEADLINE=20
    ;;
  scheduled)
    export TEST_DHCPV4_SOAK_ROUNDS=120
    export TEST_DHCPV4_SOAK_BATCH_SIZE=24
    export TEST_DHCPV4_SOAK_POST_BATCH_SIZE=12
    export TEST_DHCPV4_SOAK_CAPTURE_TIMEOUT=20
    export TEST_DHCPV4_SOAK_BATCH_DEADLINE=30
    ;;
  *)
    echo "[ERROR] Unsupported profile '$PROFILE'. Use smoke or scheduled."
    exit 2
    ;;
esac

export TEST_DHCPV4_SOAK_RELEASE_SETTLE_SECONDS=0.2
export TEST_DHCPV4_SOAK_P95_LIMIT_MS=3000
export TEST_DHCPV4_SOAK_LATENCY_GROWTH_LIMIT_MS=500
export TEST_DHCPV4_SOAK_MEMORY_GROWTH_LIMIT_MIB=64
export TEST_DHCPV4_SOAK_PIDS_GROWTH_LIMIT=8

STATE_DIR="${SCRIPT_DIR}/test-state"
STATE_FILE="${STATE_DIR}/dhcpv4-soak-state.json"
READY_MARKER="${STATE_DIR}/dhcpv4-soak-ready"
RESOURCE_FILE="${STATE_DIR}/dhcpv4-soak-resources.ndjson"
mkdir -p "$STATE_DIR"
rm -f "$STATE_FILE" "$READY_MARKER" "$RESOURCE_FILE"

cleanup() {
  docker compose "${COMPOSE[@]}" down >/dev/null 2>&1 || true
  rm -f "$STATE_FILE" "$READY_MARKER" "$RESOURCE_FILE"
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

wait_for_ready() {
  local attempt
  for attempt in $(seq 1 240); do
    if [[ -f "$READY_MARKER" ]]; then
      return 0
    fi
    sleep 0.5
  done
  echo "[ERROR] Timed out waiting for the first completed soak batch"
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
  TEST_RESULTS_DIR="/app/test-results/soak-${SERVER}-${SERVER_VERSION}-${PROFILE}-${suffix}" \
    docker compose "${COMPOSE[@]}" run --rm --no-deps test-runner
}

echo "[INFO] Starting soak fixture server=${SERVER} version=${SERVER_VERSION} profile=${PROFILE}"
docker compose "${COMPOSE[@]}" up -d --build dhcp-server
wait_for_health

capture_resource_sample
run_phase soak_run run &
soak_pid=$!
wait_for_ready

echo "[INFO] Sampling server CPU, memory, and PID usage during lease churn"
while kill -0 "$soak_pid" 2>/dev/null; do
  capture_resource_sample
  sleep 1
done
wait "$soak_pid"
capture_resource_sample

run_phase soak_verify verify

echo "[INFO] DHCPv4 soak profile passed for ${SERVER}/${SERVER_VERSION}/${PROFILE}"
