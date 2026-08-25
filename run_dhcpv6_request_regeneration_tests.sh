#!/usr/bin/env bash
# Prove that an identical DHCPv6 REQUEST is processed again by the target.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

if [[ -z "${TEST_DHCPV6_REQUEST_COUNTER_COMMAND:-}" ]]; then
  echo "[ERROR] TEST_DHCPV6_REQUEST_COUNTER_COMMAND is required." >&2
  echo "[ERROR] The adapter must print the matching REQUEST count." >&2
  exit 2
fi

export TEST_CAPABILITIES="dhcpv6_request_observability"
export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_RESULTS_RUN_SUFFIX=request-regeneration

exec bash "$SCRIPT_DIR/run_dhcp_tests.sh" \
  --server kea \
  --ip-version v6 \
  --tags @rfc9915_request_regeneration \
  "$@"
