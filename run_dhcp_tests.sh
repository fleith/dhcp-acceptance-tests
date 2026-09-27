#!/usr/bin/env bash
# Run DHCP acceptance tests using docker compose.
#
# Usage:
#   bash ./run_dhcp_tests.sh [--server isc-dhcpd|kea] [--ip-version v4|v6|dual]
#       [--server-version baseline|isc-final|kea-lts|kea-stable]
#       [--compose-file PATH]
#       [--tags TAG_EXPRESSION]... [-- <extra compose args>]
#
# Examples:
#   bash ./run_dhcp_tests.sh
#   bash ./run_dhcp_tests.sh --server kea
#   bash ./run_dhcp_tests.sh --ip-version v6
#   bash ./run_dhcp_tests.sh --server kea --ip-version dual
#   bash ./run_dhcp_tests.sh --server kea --server-version kea-stable --ip-version v6
#   bash ./run_dhcp_tests.sh --server kea --ip-version v6 --tags @known_divergence --tags @ipv6

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
source "${SCRIPT_DIR}/lib/common.sh"


SERVER="isc-dhcpd"
IP_VERSION="v4"
SERVER_VERSION="baseline"
BEHAVE_TAGS=()
ADDITIONAL_COMPOSE_FILES=()
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
    --server-version)
      [[ $# -ge 2 ]] || { echo "[ERROR] --server-version requires a value"; exit 2; }
      SERVER_VERSION="$2"
      shift 2
      ;;
    --tags)
      [[ $# -ge 2 ]] || { echo "[ERROR] --tags requires a value"; exit 2; }
      BEHAVE_TAGS+=("$2")
      shift 2
      ;;
    --compose-file)
      [[ $# -ge 2 ]] || { echo "[ERROR] --compose-file requires a value"; exit 2; }
      ADDITIONAL_COMPOSE_FILES+=(-f "$2")
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
  select_server_profile "$SERVER" "$SERVER_VERSION" "$mode"
  
  case "$mode" in
    v4)
      ;;
    v6)
      COMPOSE+=(-f "${PROJECT_ROOT}/docker-compose.ipv6.yml")
      ;;
    *)
      echo "[ERROR] Unsupported mode '$mode'. Use 'v4' or 'v6'."
      exit 2
      ;;
  esac

  COMPOSE+=("${ADDITIONAL_COMPOSE_FILES[@]}")
}

configure_version_profile() {
  local mode="$1"

  unset ISC_DHCP_BASE_IMAGE KEA_BASE_IMAGE KEA_DDNS_IMAGE KEA_INSTALL_MODE TEST_BEHAVE_ARGS
  unset TEST_RESULTS_DIR
  export TEST_SERVER_VERSION="$SERVER_VERSION"

  # select_server_profile validates the server/version pair.
  case "$SERVER_VERSION" in
    baseline) VERSION_LABEL="distribution baseline" ;;
    isc-final) VERSION_LABEL="ISC DHCP 4.4.3-P1 final release line" ;;
    kea-lts) VERSION_LABEL="Kea ${KEA_LTS_VERSION} LTS" ;;
    kea-stable) VERSION_LABEL="Kea ${KEA_STABLE_VERSION} stable" ;;
  esac

  # Tag-filtered runs get their own results directory so they don't replace the full run's reports.
  local tags_suffix=""
  if (( ${#BEHAVE_TAGS[@]} > 0 )); then
    local tag
    local quoted_tag
    local tag_args=""
    for tag in "${BEHAVE_TAGS[@]}"; do
      printf -v quoted_tag '%q' "$tag"
      tag_args+=" --tags=${quoted_tag}"
      tag="${tag//\~@/not-}"
      tag="${tag// /-}"
      tags_suffix+="${tags_suffix:+-}${tag//[^A-Za-z0-9_-]/}"
    done
    export TEST_BEHAVE_ARGS="${tag_args# }"
  fi

  local results_suffix="${TEST_RESULTS_RUN_SUFFIX:-$tags_suffix}"
  export TEST_RESULTS_DIR="/app/test-results/${SERVER}-${SERVER_VERSION}-${mode}${results_suffix:+-${results_suffix}}"
}

COMPOSE=()
stop_stack() {
  if (( ${#COMPOSE[@]} > 0 )); then
    compose_down
  fi
}
# Also tear down when interrupted or when a step fails under set -e.
trap stop_stack EXIT

run_once() {
  local mode="$1"
  local rc=0
  local up_args=(--abort-on-container-exit --exit-code-from test-runner)

  configure_version_profile "$mode"
  build_compose_files "$mode"

  # Build arguments select the requested server release profile.
  up_args+=(--build)

  ensure_host_dirs

  echo "[INFO] Running tests against server=${SERVER} ip_version=${mode} version=${VERSION_LABEL}"
  docker compose "${COMPOSE[@]}" up "${up_args[@]}" "${EXTRA_ARGS[@]}" || rc=$?

  echo "[INFO] Stopping docker compose stack for ip_version=${mode}..."
  stop_stack

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
