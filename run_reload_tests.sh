#!/usr/bin/env bash
# Change Kea policy with SIGHUP while a live lease remains active.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
STATE_DIR="${SCRIPT_DIR}/test-state"
REQUEST="${STATE_DIR}/reload.request"
COMPLETE="${STATE_DIR}/reload.complete"
TEST_PID=""

mkdir -p "$STATE_DIR"
rm -f "$REQUEST" "$COMPLETE"

cleanup() {
  if [[ -n "$TEST_PID" ]] && kill -0 "$TEST_PID" 2>/dev/null; then
    kill "$TEST_PID" 2>/dev/null || true
  fi
  docker compose -f "${SCRIPT_DIR}/docker-compose.yml" \
    -f "${SCRIPT_DIR}/docker-compose.kea.yml" down -v >/dev/null 2>&1 || true
  rm -f "$REQUEST" "$COMPLETE"
}
trap cleanup EXIT

export TEST_CAPABILITIES=reload
export TEST_RELOAD_COMMAND="python3 /app/adapters/orchestrated_action.py reload"
export TEST_RELOADED_CLASS_DOMAIN=reloaded.acceptance.test
export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_RESULTS_RUN_SUFFIX=live-reload

bash "${SCRIPT_DIR}/run_dhcp_tests.sh" \
  --server kea \
  --server-version kea-stable \
  --ip-version v4 \
  --tags @requires_reload &
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
  echo "[ERROR] Reload scenario did not request its host action" >&2
  exit 1
fi

MSYS_NO_PATHCONV=1 docker exec dhcp-test-server sed -i \
  's/class\.acceptance\.test/reloaded.acceptance.test/g' \
  /etc/kea/kea-dhcp4.conf
docker kill --signal HUP dhcp-test-server >/dev/null
sleep 1

if ! docker logs dhcp-test-server 2>&1 | grep -q 'DHCP4_DYNAMIC_RECONFIGURATION_SUCCESS'; then
  printf '%s\n' 'error:Kea did not report a completed SIGHUP reload' > "$COMPLETE"
else
  printf '%s\n' ok > "$COMPLETE"
fi

wait "$TEST_PID"
TEST_PID=""
echo "[INFO] Live configuration reload profile passed for Kea 3.2.0"
