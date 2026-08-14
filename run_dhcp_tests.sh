#!/usr/bin/env bash
# Run DHCP acceptance tests using docker compose.
#
# Usage:
#   bash ./run_dhcp_tests.sh [--server isc-dhcpd|kea] [--ip-version v4|v6|dual]
#       [--server-version baseline|isc-final|kea-lts|kea-stable]
#       [--tags TAG_EXPRESSION]... [-- <extra compose args>]
#
# Examples:
#   bash ./run_dhcp_tests.sh
#   bash ./run_dhcp_tests.sh --server kea
#   bash ./run_dhcp_tests.sh --ip-version v6
#   bash ./run_dhcp_tests.sh --server kea --ip-version dual
#   bash ./run_dhcp_tests.sh --server kea --server-version kea-stable --ip-version v6
#   bash ./run_dhcp_tests.sh --server kea --ip-version v6 --tags @known_divergence

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"

# Git Bash rewrites container paths such as /app before invoking Docker.
case "$(uname -s)" in
  MINGW*|MSYS*)
    export MSYS2_ENV_CONV_EXCL="TEST_RESULTS_DIR${MSYS2_ENV_CONV_EXCL:+;${MSYS2_ENV_CONV_EXCL}}"
    ;;
esac

SERVER="isc-dhcpd"
IP_VERSION="v4"
SERVER_VERSION="baseline"
BEHAVE_TAGS=()
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

configure_version_profile() {
  local mode="$1"

  unset ISC_DHCP_BASE_IMAGE KEA_BASE_IMAGE KEA_INSTALL_MODE TEST_BEHAVE_ARGS
  unset TEST_RESULTS_DIR

  case "$SERVER_VERSION" in
    baseline)
      VERSION_LABEL="distribution baseline"
      ;;
    isc-final)
      [[ "$SERVER" == "isc-dhcpd" ]] || {
        echo "[ERROR] isc-final requires --server isc-dhcpd"
        exit 2
      }
      export ISC_DHCP_BASE_IMAGE="debian:bookworm-slim"
      VERSION_LABEL="ISC DHCP 4.4.3-P1 final release line"
      ;;
    kea-lts|kea-stable)
      [[ "$SERVER" == "kea" ]] || {
        echo "[ERROR] $SERVER_VERSION requires --server kea"
        exit 2
      }
      local kea_version
      if [[ "$SERVER_VERSION" == "kea-lts" ]]; then
        kea_version="3.0.3"
        VERSION_LABEL="Kea 3.0.3 LTS"
      else
        kea_version="3.2.0"
        VERSION_LABEL="Kea 3.2.0 stable"
      fi
      export KEA_BASE_IMAGE="docker.cloudsmith.io/isc/docker/kea-dhcp${mode#v}:${kea_version}"
      export KEA_INSTALL_MODE="alpine"
      ;;
    *)
      echo "[ERROR] Unsupported server version '$SERVER_VERSION'." \
           "Use baseline, isc-final, kea-lts, or kea-stable."
      exit 2
      ;;
  esac

  if (( ${#BEHAVE_TAGS[@]} > 0 )); then
    local tag
    local quoted_tag
    local tag_args=""
    for tag in "${BEHAVE_TAGS[@]}"; do
      printf -v quoted_tag '%q' "$tag"
      tag_args+=" --tags=${quoted_tag}"
    done
    export TEST_BEHAVE_ARGS="${tag_args# }"
  fi

  local results_suffix="${TEST_RESULTS_RUN_SUFFIX:-}"
  export TEST_RESULTS_DIR="/app/test-results/${SERVER}-${SERVER_VERSION}-${mode}${results_suffix:+-${results_suffix}}"
}

run_once() {
  local mode="$1"
  local rc=0
  local up_args=(--abort-on-container-exit --exit-code-from test-runner)

  configure_version_profile "$mode"
  build_compose_files "$mode"

  # Build arguments select the requested server release profile.
  up_args+=(--build)

  echo "[INFO] Running tests against server=${SERVER} ip_version=${mode} version=${VERSION_LABEL}"
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
