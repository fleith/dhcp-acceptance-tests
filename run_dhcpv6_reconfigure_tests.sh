#!/usr/bin/env bash
# Run the capability-gated RFC 9915 authenticated Reconfigure profile.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

if [[ -z "${TEST_RECONFIGURE_TRIGGER_COMMAND:-}" ]]; then
  echo "[ERROR] TEST_RECONFIGURE_TRIGGER_COMMAND is required." >&2
  echo "[ERROR] Supply a target-service compose override and trigger adapter." >&2
  exit 2
fi

export TEST_CAPABILITIES="authenticated_reconfigure"
export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_RESULTS_RUN_SUFFIX=authenticated-reconfigure

exec bash "$SCRIPT_DIR/run_dhcp_tests.sh" \
  --server kea \
  --ip-version v6 \
  --tags @requires_authenticated_reconfigure \
  "$@"
