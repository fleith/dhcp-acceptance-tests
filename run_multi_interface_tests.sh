#!/usr/bin/env bash
# Verify direct DHCPv4 allocation and scope isolation on two interfaces.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

export TEST_CAPABILITIES=multi_interface
export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_RESULTS_RUN_SUFFIX=multi-interface

exec bash "${SCRIPT_DIR}/run_dhcp_tests.sh" \
  --server kea \
  --server-version kea-stable \
  --ip-version v4 \
  --compose-file "${SCRIPT_DIR}/docker-compose.multi-interface.yml" \
  --tags @requires_multi_interface
