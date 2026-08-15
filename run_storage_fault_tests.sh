#!/usr/bin/env bash
# Exhaust the live DHCPv4 lease directory, then verify durable recovery.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$(uname -s)" in
  MINGW*|MSYS*)
    export MSYS2_ENV_CONV_EXCL="TEST_RESULTS_DIR;DHCPV4_STORAGE_TARGET${MSYS2_ENV_CONV_EXCL:+;${MSYS2_ENV_CONV_EXCL}}"
    ;;
esac

SERVER="isc-dhcpd"
SERVER_VERSION="baseline"

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

COMPOSE=(-f "${SCRIPT_DIR}/docker-compose.yml")
case "$SERVER" in
  isc-dhcpd)
    STORAGE_DIR="/data"
    LEASE_FILE="/data/dhcpd.leases"
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
    STORAGE_DIR="/var/lib/kea"
    LEASE_FILE="/var/lib/kea/kea-leases4.csv"
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

COMPOSE+=(-f "${SCRIPT_DIR}/docker-compose.storage-fault.yml")

export DHCPV4_POOL_START_OFFSET=190
export DHCPV4_POOL_END_OFFSET=200
export DHCPV4_ALT_POOL_ENABLED=0
export DHCPV4_STORAGE_TARGET="$STORAGE_DIR"
export TEST_DHCPV4_STORAGE_BASELINE_CLIENTS=10
export TEST_DHCPV4_STORAGE_POOL_CAPACITY=11
export TEST_DHCPV4_STORAGE_FAULT_TIMEOUT=4
export TEST_DHCPV4_STORAGE_RECOVERY_TIMEOUT=10

STATE_DIR="${SCRIPT_DIR}/test-state"
STATE_FILE="${STATE_DIR}/dhcpv4-storage-fault-state.json"
FAULT_MARKER="${STATE_DIR}/dhcpv4-storage-fault-active"
BACKING_IMAGE="/storage-fault-backing/lease-store.ext4"
FILL_FILE="${STORAGE_DIR}/.storage-fault-fill"
LOG_DIR="${SCRIPT_DIR}/test-results/storage-fault-${SERVER}-${SERVER_VERSION}-server"
RUNNER_CONTAINER="dhcp-storage-fault-runner"
mkdir -p "$STATE_DIR" "$LOG_DIR"
rm -f "$STATE_FILE" "$FAULT_MARKER"

cleanup() {
  if [[ -f "$FAULT_MARKER" ]] && \
     [[ "$(docker inspect --format '{{.State.Running}}' dhcp-test-server 2>/dev/null || true)" == "true" ]]; then
    MSYS_NO_PATHCONV=1 docker exec dhcp-test-server \
      rm -f "$FILL_FILE" >/dev/null 2>&1 || true
  fi
  docker rm -f "$RUNNER_CONTAINER" >/dev/null 2>&1 || true
  docker compose "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  rm -f "$STATE_FILE" "$FAULT_MARKER"
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

run_phase() {
  local phase="$1"
  local suffix="$2"
  MSYS_NO_PATHCONV=1 docker exec \
    -e TEST_BEHAVE_ARGS="--tags=@orchestrated --tags=@${phase} --no-skipped" \
    -e TEST_REQUIRE_EXECUTED_SCENARIOS=1 \
    -e TEST_RESULTS_DIR="/app/test-results/storage-fault-${SERVER}-${SERVER_VERSION}-${suffix}" \
    "$RUNNER_CONTAINER" python3 run_tests.py
}

start_test_runner() {
  docker compose "${COMPOSE[@]}" build test-runner
  docker compose "${COMPOSE[@]}" run -d --name "$RUNNER_CONTAINER" \
    --no-deps --entrypoint sleep test-runner infinity
  local attempt
  for attempt in $(seq 1 60); do
    if docker exec "$RUNNER_CONTAINER" python3 -c \
      "import behave, dns, scapy" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  docker logs "$RUNNER_CONTAINER"
  echo "[ERROR] Storage-fault test runner did not become ready"
  return 1
}

verify_lease_store() {
  MSYS_NO_PATHCONV=1 docker exec dhcp-test-server sh -c \
    "test -f '${LEASE_FILE}' && test -s '${LEASE_FILE}' && sync"
}

exhaust_lease_storage() {
  MSYS_NO_PATHCONV=1 docker exec dhcp-test-server sh -c \
    "rm -f '${FILL_FILE}' '${STORAGE_DIR}/.storage-fault-probe'; sync; \
     status=0; dd if=/dev/zero of='${FILL_FILE}' bs=1M count=64 2>/dev/null || status=\$?; \
     test \"\$status\" -ne 0; sync || true; \
     ! dd if=/dev/zero of='${STORAGE_DIR}/.storage-fault-probe' bs=4096 count=1 2>/dev/null"
  printf '%s\n' "${SERVER} lease filesystem exhausted" > "$FAULT_MARKER"
}

restore_lease_capacity() {
  local server_image
  server_image="$(docker inspect --format '{{.Config.Image}}' dhcp-test-server)"
  MSYS_NO_PATHCONV=1 docker run --rm --privileged \
    --volumes-from dhcp-test-server --entrypoint sh "$server_image" -c \
    "mkdir -p /storage-fault-recovery; \
     mount -o loop,rw '${BACKING_IMAGE}' /storage-fault-recovery; \
     rm -f '/storage-fault-recovery/.storage-fault-fill' \
           '/storage-fault-recovery/.storage-fault-probe'; \
     sync; umount /storage-fault-recovery"
  rm -f "$FAULT_MARKER"
}

capture_server_evidence() {
  docker compose "${COMPOSE[@]}" logs --no-color dhcp-server \
    > "${LOG_DIR}/dhcp-server.log" 2>&1 || true
  docker inspect dhcp-test-server \
    > "${LOG_DIR}/container-inspect.json" 2>&1 || true
}

stop_faulted_server() {
  if [[ "$(docker inspect --format '{{.State.Running}}' dhcp-test-server 2>/dev/null || true)" == "true" ]]; then
    docker compose "${COMPOSE[@]}" kill -s SIGKILL dhcp-server
  fi
}

echo "[INFO] Starting storage-fault fixture server=${SERVER} version=${SERVER_VERSION}"
docker compose "${COMPOSE[@]}" up -d --build dhcp-server
wait_for_health
start_test_runner
run_phase storage_fault_prepare prepare
verify_lease_store

echo "[INFO] Exhausting ${STORAGE_DIR} during a new lease transaction"
exhaust_lease_storage
run_phase storage_fault_inject inject
capture_server_evidence

echo "[INFO] Discarding fault-time memory state and restoring writable storage"
stop_faulted_server
restore_lease_capacity
docker compose "${COMPOSE[@]}" start dhcp-server
wait_for_health
MSYS_NO_PATHCONV=1 docker exec dhcp-test-server sh -c \
  "touch '${STORAGE_DIR}/.storage-recovery-probe' && rm -f '${STORAGE_DIR}/.storage-recovery-probe'"

run_phase storage_fault_verify verify

echo "[INFO] Runtime storage-fault profile passed for ${SERVER}/${SERVER_VERSION}"
