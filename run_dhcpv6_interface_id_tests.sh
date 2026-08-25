#!/usr/bin/env bash
# Run the isolated RFC 9915 opaque Interface-ID assignment-policy profile.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

export TEST_CAPABILITIES="dhcpv6_interface_id_policy"
export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_RESULTS_RUN_SUFFIX=interface-id-policy

exec bash "$SCRIPT_DIR/run_dhcp_tests.sh" \
  --server kea \
  --server-version kea-stable \
  --ip-version v6 \
  --compose-file "$SCRIPT_DIR/docker-compose.ipv6-interface-id.yml" \
  --tags @requires_dhcpv6_interface_id_policy \
  "$@"
