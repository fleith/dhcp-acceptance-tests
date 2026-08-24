#!/usr/bin/env bash
# Verify RFC 9915 unknown-binding REBIND behavior with creation disabled.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

export DHCPV6_RAPID_COMMIT=0
export TEST_CAPABILITIES=""
export TEST_REQUIRE_EXECUTED_SCENARIOS=1

exec bash "$SCRIPT_DIR/run_dhcp_tests.sh" \
  --ip-version v6 \
  --tags @orchestrated \
  --tags @rfc9915_rebind_disabled \
  --tags @known_divergence \
  "$@"
