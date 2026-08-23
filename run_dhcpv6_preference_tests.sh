#!/usr/bin/env bash
# Verify the configurable nonzero RFC 9915 server Preference path.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

export DHCPV6_PREFERENCE="${DHCPV6_PREFERENCE:-200}"
export TEST_DHCPV6_EXPECTED_PREFERENCE="$DHCPV6_PREFERENCE"
export TEST_REQUIRE_EXECUTED_SCENARIOS=1

exec bash "$SCRIPT_DIR/run_dhcp_tests.sh" \
  --ip-version v6 \
  --tags @rfc9915_preference \
  "$@"
