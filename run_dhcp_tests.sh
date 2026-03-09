#!/usr/bin/env bash
# Run DHCP acceptance tests using docker compose.
#
# Usage:
#   ./run_dhcp_tests.sh [--server isc-dhcpd|kea] [--ip-version v4|v6|dual] [-- <extra compose args>]
#
# Examples:
#   ./run_dhcp_tests.sh
#   ./run_dhcp_tests.sh --server kea
#   ./run_dhcp_tests.sh --ip-version v6
#   ./run_dhcp_tests.sh --server kea --ip-version dual

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"

SERVER="isc-dhcpd"
IP_VERSION="v4"
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      [[ $# -ge 2 ]] || { echo "[ERROR] --server requires a value"; exit 2; }
      SERVER="$2"
      shift 2
      ;;
    --ip-version)
      [[ $# -ge 2 ]] || { echo "[ERROR] --ip-version requires a value"; exit 2; }
      IP_VERSION="$2"
      shift 2
      ;;
    --)
      shift
      EXTRA_ARGS+=("$@")
      break
      ;;
    *)
      EXTRA_ARGS+=("$1")
      shift
      ;;
  esac
done

build_compose_files() {
  local mode="$1"
  COMPOSE_FILES=(-f "${PROJECT_ROOT}/docker-compose.yml")

  case "$SERVER" in
    isc-dhcpd)
      ;;
    kea)
      COMPOSE_FILES+=(-f "${PROJECT_ROOT}/docker-compose.kea.yml")
      ;;
    *)
      echo "[ERROR] Unsupported server '$SERVER'. Use 'isc-dhcpd' or 'kea'."
      exit 2
      ;;
  esac

  case "$mode" in
    v4)
      ;;
    v6)
      COMPOSE_FILES+=(-f "${PROJECT_ROOT}/docker-compose.ipv6.yml")
      ;;
    *)
      echo "[ERROR] Unsupported mode '$mode'. Use 'v4' or 'v6'."
      exit 2
      ;;
  esac
}

run_once() {
  local mode="$1"
  local rc=0
  local up_args=(--abort-on-container-exit --exit-code-from test-runner)

  if [[ "$SERVER" == "kea" && "$mode" == "v6" ]]; then
    echo "[ERROR] --server kea with --ip-version v6 is currently unsupported in this topology (Kea DHCPv6 socket bind issue in Docker bridge mode)."
    return 2
  fi

  build_compose_files "$mode"

  if [[ "$SERVER" == "kea" ]]; then
    # Ensure the selected Kea image (dhcp4 or dhcp6 entrypoint) is rebuilt.
    up_args+=(--build)
  fi

  echo "[INFO] Running tests against server=${SERVER} ip_version=${mode}"
  docker compose "${COMPOSE_FILES[@]}" up "${up_args[@]}" "${EXTRA_ARGS[@]}" || rc=$?

  echo "[INFO] Stopping docker compose stack for ip_version=${mode}..."
  docker compose "${COMPOSE_FILES[@]}" down >/dev/null 2>&1 || true

  return $rc
}

case "$IP_VERSION" in
  v4)
    run_once v4
    ;;
  v6)
    run_once v6
    ;;
  dual)
    run_once v4
    run_once v6
    ;;
  *)
    echo "[ERROR] Unsupported --ip-version '$IP_VERSION'. Use v4, v6, or dual."
    exit 2
    ;;
esac