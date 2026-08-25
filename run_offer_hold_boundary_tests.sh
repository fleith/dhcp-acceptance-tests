#!/usr/bin/env bash
# Exercise a target's configured DHCPv4 offer-hold expiry boundary.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

if [[ -z "${TEST_DHCPV4_OFFER_HOLD_EXPIRY_SECONDS:-}" ]]; then
  echo "[ERROR] TEST_DHCPV4_OFFER_HOLD_EXPIRY_SECONDS is required." >&2
  echo "[ERROR] Set it to the target's configured offer-hold duration." >&2
  exit 2
fi

export TEST_CAPABILITIES="offer_hold_expiry"
export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_RESULTS_RUN_SUFFIX=offer-hold-boundary

exec bash "$SCRIPT_DIR/run_dhcp_tests.sh" \
  --server kea \
  --ip-version v4 \
  --tags @offer_hold_boundary \
  "$@"
