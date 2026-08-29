#!/usr/bin/env bash
# Prove that REBIND returns only resources owned by the requesting client.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_RESULTS_RUN_SUFFIX=rebind-ownership

exec bash "$SCRIPT_DIR/run_dhcp_tests.sh" \
  --server kea \
  --ip-version v6 \
  --tags @rfc9915_rebind_ownership \
  "$@"
