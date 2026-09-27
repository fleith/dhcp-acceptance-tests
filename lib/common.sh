# Shared setup for the run_*.sh scripts. Source it after setting SCRIPT_DIR.

KEA_LTS_VERSION="3.0.3"
KEA_STABLE_VERSION="3.2.0"

# Git Bash rewrites container paths such as /app unless these variables are
# excluded from MSYS path conversion.
case "$(uname -s)" in
  MINGW*|MSYS*)
    export MSYS2_ENV_CONV_EXCL="TEST_RESULTS_DIR;DHCPV4_SERVER_LOG_FILE;TEST_DHCPV4_SERVER_LOG_FILE;DHCPV4_STORAGE_TARGET${MSYS2_ENV_CONV_EXCL:+;${MSYS2_ENV_CONV_EXCL}}"
    ;;
esac

# select_server_profile SERVER SERVER_VERSION [v4|v6]
# Sets COMPOSE to the server's compose files and exports its image build arguments.
select_server_profile() {
  local server="$1"
  local version="$2"
  local mode="${3:-v4}"
  local kea_version=""
  COMPOSE=(-f "${SCRIPT_DIR}/docker-compose.yml")
  case "$server" in
    isc-dhcpd)
      case "$version" in
        baseline) ;;
        isc-final) export ISC_DHCP_BASE_IMAGE="debian:bookworm-slim" ;;
        *) echo "[ERROR] ISC DHCP requires baseline or isc-final"; exit 2 ;;
      esac
      ;;
    kea)
      COMPOSE+=(-f "${SCRIPT_DIR}/docker-compose.kea.yml")
      case "$version" in
        baseline) ;;
        kea-lts) kea_version="$KEA_LTS_VERSION" ;;
        kea-stable) kea_version="$KEA_STABLE_VERSION" ;;
        *) echo "[ERROR] Kea requires baseline, kea-lts, or kea-stable"; exit 2 ;;
      esac
      if [[ -n "$kea_version" ]]; then
        export KEA_BASE_IMAGE="docker.cloudsmith.io/isc/docker/kea-dhcp${mode#v}:${kea_version}"
        export KEA_DDNS_IMAGE="docker.cloudsmith.io/isc/docker/kea-dhcp-ddns:${kea_version}"
        export KEA_INSTALL_MODE="alpine"
      fi
      ;;
    *)
      echo "[ERROR] Unsupported server '$server'. Use isc-dhcpd or kea."
      exit 2
      ;;
  esac
}

# Create the bind-mount sources as the invoking user; Docker would create them as root.
ensure_host_dirs() {
  mkdir -p "${SCRIPT_DIR}/test-state" "${SCRIPT_DIR}/test-results"
}

# Remove the stack's containers, anonymous volumes, and overlay services from other runs.
compose_down() {
  docker compose "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}

# wait_for_health [CONTAINER] [ATTEMPTS]  (polls every 0.5 s)
wait_for_health() {
  local container="${1:-dhcp-test-server}"
  local attempts="${2:-60}"
  local attempt
  for attempt in $(seq 1 "$attempts"); do
    if [[ "$(docker inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null || true)" == "healthy" ]]; then
      return 0
    fi
    sleep 0.5
  done
  docker logs "$container" || true
  echo "[ERROR] $container did not become healthy" >&2
  return 1
}
