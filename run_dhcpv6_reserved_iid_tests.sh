#!/usr/bin/env bash
# Exercise allocator behavior when configured pools contain reserved IPv6 IIDs.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_RESULTS_RUN_SUFFIX=reserved-iid-pools

exec bash "$SCRIPT_DIR/run_dhcp_tests.sh" \
  --server kea \
  --server-version kea-stable \
  --ip-version v6 \
  --compose-file "$SCRIPT_DIR/docker-compose.ipv6-reserved-iid.yml" \
  --tags @orchestrated \
  --tags @known_divergence \
  --tags @rfc9915_reserved_iid_pool_divergence \
  "$@"
