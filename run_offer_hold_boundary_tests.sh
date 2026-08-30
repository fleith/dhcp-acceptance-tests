#!/usr/bin/env bash
# Exercise a DHCPv4 server's configured offer-hold expiry boundary.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

export DHCPV4_OFFER_LIFETIME="${DHCPV4_OFFER_LIFETIME:-2}"
export TEST_DHCPV4_OFFER_HOLD_EXPIRY_SECONDS="${TEST_DHCPV4_OFFER_HOLD_EXPIRY_SECONDS:-$DHCPV4_OFFER_LIFETIME}"

export TEST_CAPABILITIES="offer_hold_expiry"
export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_RESULTS_RUN_SUFFIX=offer-hold-boundary

exec bash "$SCRIPT_DIR/run_dhcp_tests.sh" \
  --server kea \
  --server-version kea-stable \
  --ip-version v4 \
  --tags @requires_offer_hold_expiry \
  "$@"
