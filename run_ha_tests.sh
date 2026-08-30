#!/usr/bin/env bash
# Exercise Kea hot-standby lease replication and automatic failover.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
COMPOSE=(-f "${SCRIPT_DIR}/docker-compose.yml" -f "${SCRIPT_DIR}/docker-compose.kea.yml" -f "${SCRIPT_DIR}/docker-compose.ha.yml")
STATE_DIR="${SCRIPT_DIR}/test-state"
REQUEST="${STATE_DIR}/ha-failover.request"
COMPLETE="${STATE_DIR}/ha-failover.complete"
TEST_PID=""

mkdir -p "$STATE_DIR"
rm -f "$REQUEST" "$COMPLETE"

cleanup() {
  if [[ -n "$TEST_PID" ]] && kill -0 "$TEST_PID" 2>/dev/null; then
    kill "$TEST_PID" 2>/dev/null || true
  fi
  docker compose "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  rm -f "$REQUEST" "$COMPLETE"
}
trap cleanup EXIT

wait_for_health() {
  local container="$1"
  for _attempt in $(seq 1 120); do
    if [[ "$(docker inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null || true)" == "healthy" ]]; then
      return 0
    fi
    sleep 0.5
  done
  docker logs "$container" || true
  echo "[ERROR] $container did not become healthy" >&2
  return 1
}

export KEA_BASE_IMAGE="docker.cloudsmith.io/isc/docker/kea-dhcp4:3.2.0"
export KEA_INSTALL_MODE=alpine
export TEST_SERVER_IMPL=kea
export TEST_SERVER_VERSION=kea-stable
export TEST_CAPABILITIES=ha
export TEST_HA_FAILOVER_COMMAND="python3 /app/adapters/orchestrated_action.py ha-failover"
export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_BEHAVE_ARGS="--tags=@requires_ha"
export TEST_RESULTS_DIR=/app/test-results/kea-kea-stable-v4-ha

docker compose "${COMPOSE[@]}" up -d --build dhcp-server dhcp-secondary
wait_for_health dhcp-test-server
wait_for_health dhcp-test-server-secondary

docker compose "${COMPOSE[@]}" run --rm --no-deps test-runner &
TEST_PID=$!

for _attempt in $(seq 1 180); do
  [[ -f "$REQUEST" ]] && break
  if ! kill -0 "$TEST_PID" 2>/dev/null; then
    wait "$TEST_PID"
    exit $?
  fi
  sleep 0.5
done

if [[ ! -f "$REQUEST" ]]; then
  echo "[ERROR] HA scenario did not request primary isolation" >&2
  exit 1
fi

docker kill --signal KILL dhcp-test-server >/dev/null

partner_down=0
for _attempt in $(seq 1 50); do
  if docker logs dhcp-test-server-secondary 2>&1 | grep -qi 'partner-down'; then
    partner_down=1
    break
  fi
  sleep 0.4
done

if [[ "$partner_down" -eq 1 ]]; then
  printf '%s\n' ok > "$COMPLETE"
else
  printf '%s\n' 'error:standby did not enter partner-down after primary failure' > "$COMPLETE"
fi

wait "$TEST_PID"
TEST_PID=""
echo "[INFO] Kea 3.2.0 hot-standby failover profile passed"
