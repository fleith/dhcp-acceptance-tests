#!/usr/bin/env bash
# Prove that an identical DHCPv6 REQUEST is processed again by the target.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

if [[ -z "${TEST_DHCPV6_REQUEST_COUNTER_COMMAND:-}" ]]; then
  export TEST_DHCPV6_REQUEST_COUNTER_COMMAND="python3 /app/adapters/kea_dhcpv6_request_counter.py"
fi

export TEST_CAPABILITIES="dhcpv6_request_observability"
export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_RESULTS_RUN_SUFFIX=request-regeneration

exec bash "$SCRIPT_DIR/run_dhcp_tests.sh" \
  --server kea \
  --ip-version v6 \
  --compose-file "$SCRIPT_DIR/docker-compose.ipv6-request-observability.yml" \
  --tags @capability \
  --tags @rfc9915_request_regeneration \
  "$@"
