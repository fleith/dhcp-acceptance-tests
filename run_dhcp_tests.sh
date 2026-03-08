#!/usr/bin/env bash
# Run DHCP acceptance tests using docker compose.
#
# Usage:
#   ./run_dhcp_tests.sh [--server isc-dhcpd|kea] [-- <extra compose args>]
#
# Examples:
#   ./run_dhcp_tests.sh
#   ./run_dhcp_tests.sh --server kea
#   ./run_dhcp_tests.sh --server kea -- --build

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"

SERVER="isc-dhcpd"
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      [[ $# -ge 2 ]] || { echo "[ERROR] --server requires a value"; exit 2; }
      SERVER="$2"
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

COMPOSE_FILES=(-f "${PROJECT_ROOT}/docker-compose.yml")
UP_ARGS=(--abort-on-container-exit --exit-code-from test-runner)

case "$SERVER" in
  isc-dhcpd)
    ;;
  kea)
    COMPOSE_FILES+=(-f "${PROJECT_ROOT}/docker-compose.kea.yml")
    # Ensure Kea image is built instead of reusing the dhcpd image tag.
    UP_ARGS+=(--build)
    ;;
  *)
    echo "[ERROR] Unsupported server '$SERVER'. Use 'isc-dhcpd' or 'kea'."
    exit 2
    ;;
esac

cleanup() {
  echo "[INFO] Stopping docker compose stack..."
  docker compose "${COMPOSE_FILES[@]}" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[INFO] Running tests against server: ${SERVER}"
docker compose "${COMPOSE_FILES[@]}" up "${UP_ARGS[@]}" "${EXTRA_ARGS[@]}"