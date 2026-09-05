#!/usr/bin/env bash
# Run the target-service Option 82 factory namespace qualification profile.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

export TEST_CAPABILITIES="option82_factory_namespaces"
if [[ -n "${TEST_FACTORY_LIFECYCLE_COMMAND:-}" ]]; then
  export TEST_CAPABILITIES="option82_factory_namespaces,factory_lifecycle"
fi
export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_RESULTS_RUN_SUFFIX=option82-factory-namespaces

exec bash "$SCRIPT_DIR/run_dhcp_tests.sh" \
  --server kea \
  --ip-version v4 \
  --tags @requires_option82_factory_namespaces \
  --tags @option82_factory_namespaces \
  "$@"
