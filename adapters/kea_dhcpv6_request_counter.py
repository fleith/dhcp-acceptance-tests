#!/usr/bin/env python3
"""Count Kea allocation decisions for one DHCPv6 REQUEST transaction."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


REQUEST_EVENT_IDS = frozenset(
    {
        "DHCP6_LEASE_ALLOC",
        "DHCP6_LEASE_REUSE",
    }
)
EVENT_PATTERN = re.compile(r"\b(" + "|".join(sorted(REQUEST_EVENT_IDS)) + r")\b")
TRID_PATTERN = re.compile(r"\btid=0x([0-9a-fA-F]+)\b")
DUID_PATTERN = re.compile(r"\bduid=\[([^]]+)]")


def normalize_duid(value: str) -> str:
    compact = re.sub(r"[^0-9a-fA-F]", "", value)
    if not compact or len(compact) % 2:
        raise ValueError("TEST_DHCPV6_REQUEST_DUID_HEX must contain complete octets")
    return compact.lower()


def count_matching_requests(log_text: str, transaction_id: int, duid_hex: str) -> int:
    expected_duid = normalize_duid(duid_hex)
    count = 0
    for line in log_text.splitlines():
        if EVENT_PATTERN.search(line) is None:
            continue
        transaction = TRID_PATTERN.search(line)
        duid = DUID_PATTERN.search(line)
        if transaction is None or duid is None:
            continue
        try:
            logged_transaction_id = int(transaction.group(1), 16)
            logged_duid = normalize_duid(duid.group(1))
        except ValueError:
            continue
        if logged_transaction_id == transaction_id and logged_duid == expected_duid:
            count += 1
    return count


def main() -> int:
    try:
        transaction_id = int(os.environ["TEST_DHCPV6_REQUEST_TRID"], 10)
        duid_hex = os.environ["TEST_DHCPV6_REQUEST_DUID_HEX"]
        log_file = Path(
            os.environ.get(
                "TEST_DHCPV6_REQUEST_LOG_FILE",
                "/app/test-state/dhcpv6-server.log",
            )
        )
        log_text = log_file.read_text(encoding="utf-8", errors="replace")
        count = count_matching_requests(log_text, transaction_id, duid_hex)
    except (KeyError, OSError, ValueError) as error:
        print(f"Kea DHCPv6 REQUEST counter failed: {error}", file=sys.stderr)
        return 2
    print(count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
