#!/usr/bin/env bash
# Run the isolated Kea DHCPv6 Client FQDN and live DDNS lifecycle profile.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"

export TEST_CAPABILITIES="dhcpv6_rapid_commit,dhcpv6_ddns"
export TEST_REQUIRE_EXECUTED_SCENARIOS=1
export TEST_RESULTS_RUN_SUFFIX=rfc4704-ddns

exec bash "$SCRIPT_DIR/run_dhcp_tests.sh" \
  --server kea \
  --server-version kea-stable \
  --ip-version v6 \
  --compose-file "$SCRIPT_DIR/docker-compose.ipv6-ddns.yml" \
  --tags '@rfc4704,@requires_dhcpv6_ddns' \
  "$@"
