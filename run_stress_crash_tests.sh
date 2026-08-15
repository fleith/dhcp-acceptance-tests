#!/usr/bin/env bash
# Run mixed DHCPv4 load while SIGKILLing the server, then verify durable ACKs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Git Bash rewrites container paths such as /app unless this environment value
# is explicitly excluded from MSYS path conversion.
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
export TEST_DHCPV4_STRESS_POOL_CAPACITY=101

case "$PROFILE" in
  smoke)
    export TEST_DHCPV4_STRESS_PREPARE_CLIENTS=32
    export TEST_DHCPV4_STRESS_INFLIGHT_CLIENTS=24
    export TEST_DHCPV4_STRESS_POST_CLIENTS=8
    export TEST_DHCPV4_STRESS_CHURN_ROUNDS=2
    export TEST_DHCPV4_STRESS_CHURN_BATCH=8
    export TEST_DHCPV4_STRESS_CRASH_LOAD_SECONDS=3
    export TEST_DHCPV4_STRESS_CAPTURE_TIMEOUT=10
    export TEST_DHCPV4_STRESS_BATCH_DEADLINE=20
    export TEST_DHCPV4_STRESS_P95_LIMIT_MS=3000
    ;;
  scheduled)
    export TEST_DHCPV4_STRESS_PREPARE_CLIENTS=45
    export TEST_DHCPV4_STRESS_INFLIGHT_CLIENTS=40
    export TEST_DHCPV4_STRESS_POST_CLIENTS=12
    export TEST_DHCPV4_STRESS_CHURN_ROUNDS=15
    export TEST_DHCPV4_STRESS_CHURN_BATCH=32
    export TEST_DHCPV4_STRESS_CRASH_LOAD_SECONDS=10
    export TEST_DHCPV4_STRESS_CAPTURE_TIMEOUT=20
    export TEST_DHCPV4_STRESS_BATCH_DEADLINE=30
    export TEST_DHCPV4_STRESS_P95_LIMIT_MS=3000
    ;;
  *)
    echo "[ERROR] Unsupported profile '$PROFILE'. Use smoke or scheduled."
    exit 2
    ;;
esac

STATE_DIR="${SCRIPT_DIR}/test-state"
STATE_FILE="${STATE_DIR}/dhcpv4-stress-state.json"
READY_MARKER="${STATE_DIR}/dhcpv4-stress-inflight-ready"
CRASH_MARKER="${STATE_DIR}/dhcpv4-stress-server-crashed"
mkdir -p "$STATE_DIR"
rm -f "$STATE_FILE" "$READY_MARKER" "$CRASH_MARKER"

cleanup() {
  docker compose "${COMPOSE[@]}" down >/dev/null 2>&1 || true
  rm -f "$STATE_FILE" "$READY_MARKER" "$CRASH_MARKER"
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

wait_for_marker() {
  local attempt
  for attempt in $(seq 1 240); do
    if [[ -f "$READY_MARKER" ]]; then
      return 0
    fi
    sleep 0.5
  done
  echo "[ERROR] Timed out waiting for live stress traffic marker"
  return 1
}

run_phase() {
  local phase="$1"
  local suffix="$2"
  TEST_BEHAVE_ARGS="--tags=@orchestrated --tags=@${phase} --no-skipped" \
  TEST_REQUIRE_EXECUTED_SCENARIOS=1 \
  TEST_RESULTS_DIR="/app/test-results/stress-${SERVER}-${SERVER_VERSION}-${PROFILE}-${suffix}" \
    docker compose "${COMPOSE[@]}" run --rm --no-deps test-runner
}

echo "[INFO] Starting stress fixture server=${SERVER} version=${SERVER_VERSION} profile=${PROFILE}"
docker compose "${COMPOSE[@]}" up -d --build dhcp-server
wait_for_health

run_phase stress_prepare prepare

echo "[INFO] Starting mixed allocation, renewal, and retransmission traffic"
run_phase stress_inflight inflight &
inflight_pid=$!
wait_for_marker

echo "[INFO] SIGKILLing DHCP server while mixed traffic is active"
docker compose "${COMPOSE[@]}" kill -s SIGKILL dhcp-server
printf '%s\n' "server SIGKILL completed" > "$CRASH_MARKER"
wait "$inflight_pid"

echo "[INFO] Restarting server and verifying every acknowledged binding"
docker compose "${COMPOSE[@]}" start dhcp-server
wait_for_health
run_phase stress_verify verify
run_phase stress_cleanup cleanup

echo "[INFO] DHCPv4 stress/crash profile passed for ${SERVER}/${SERVER_VERSION}/${PROFILE}"
