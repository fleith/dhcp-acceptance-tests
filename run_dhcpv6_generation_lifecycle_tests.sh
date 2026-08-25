#!/usr/bin/env bash
# Run the bounded two-subnet DHCPv6 generation/restart/reuse qualification.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

required=(
  TEST_DHCPV6_GENERATION_RESTART_COMMAND
  TEST_DHCPV6_GENERATION_RELAY_SUBNET
  TEST_DHCPV6_GENERATION_RELAY_LINK_ADDRESS
  TEST_DHCPV6_GENERATION_POOL_CAPACITY_PER_SUBNET
)
for variable in "${required[@]}"; do
  if [[ -z "${!variable:-}" ]]; then
    echo "[ERROR] ${variable} is required." >&2
    exit 2
  fi
done

export TEST_CAPABILITIES="dhcpv6_generation_lifecycle,dhcpv6_rapid_commit"
export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_RESULTS_RUN_SUFFIX=generation-lifecycle

exec bash "$SCRIPT_DIR/run_dhcp_tests.sh" \
  --server kea \
  --ip-version v6 \
  --tags @rfc9915_generation_lifecycle \
  "$@"
