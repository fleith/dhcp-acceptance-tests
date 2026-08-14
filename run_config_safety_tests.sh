#!/usr/bin/env bash
# Verify that unsafe overlapping topology and unavailable persistence fail closed.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
SERVER="isc-dhcpd"
OVERLAP_POLICY="reject"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      SERVER="$2"
      shift 2
      ;;
    --overlap-policy)
      OVERLAP_POLICY="$2"
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
  isc-dhcpd) ;;
  kea) COMPOSE+=(-f "${SCRIPT_DIR}/docker-compose.kea.yml") ;;
  *) echo "[ERROR] Unsupported server '$SERVER'"; exit 2 ;;
esac

cleanup() {
  docker compose "${COMPOSE[@]}" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

expect_startup_rejection() {
  local label="$1"
  shift
  cleanup
  set +e
  timeout 20s env "$@" docker compose "${COMPOSE[@]}" up \
    --build --no-deps --abort-on-container-exit --exit-code-from dhcp-server \
    dhcp-server
  local rc=$?
  set -e
  if ! docker inspect dhcp-test-server >/dev/null 2>&1; then
    echo "[ERROR] ${SERVER} ${label} probe never created the server container"
    return 1
  fi
  if [[ $rc -eq 0 ]]; then
    echo "[ERROR] ${SERVER} accepted unsafe ${label} configuration"
    return 1
  fi
  if [[ $rc -eq 124 ]]; then
    echo "[ERROR] ${SERVER} remained running with unsafe ${label} configuration"
    return 1
  fi
  echo "[INFO] ${SERVER} rejected ${label} configuration (exit=${rc})"
}

probe_overlap_policy() {
  cleanup
  set +e
  timeout 20s env DHCPV4_INJECT_OVERLAPPING_SUBNET=1 \
    docker compose "${COMPOSE[@]}" up \
    --build --no-deps --abort-on-container-exit --exit-code-from dhcp-server \
    dhcp-server
  local rc=$?
  set -e
  if ! docker inspect dhcp-test-server >/dev/null 2>&1; then
    echo "[ERROR] ${SERVER} overlap probe never created the server container"
    return 1
  fi
  case "$OVERLAP_POLICY" in
    reject)
      if [[ $rc -eq 0 || $rc -eq 124 ]]; then
        echo "[ERROR] ${SERVER} accepted overlapping topology; policy requires rejection"
        return 1
      fi
      ;;
    allow)
      if [[ $rc -ne 124 ]]; then
        echo "[ERROR] ${SERVER} rejected overlapping topology; policy documents acceptance"
        return 1
      fi
      ;;
    *)
      echo "[ERROR] Unsupported overlap policy '$OVERLAP_POLICY'"
      return 2
      ;;
  esac
  echo "[INFO] ${SERVER} satisfied overlap policy=${OVERLAP_POLICY}"
}

probe_overlap_policy
expect_startup_rejection unavailable-lease-storage DHCPV4_FORCE_STORAGE_FAILURE=1
