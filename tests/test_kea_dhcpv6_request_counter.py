import unittest

from adapters.kea_dhcpv6_request_counter import count_matching_requests, normalize_duid


class KeaDhcpv6RequestCounterTests(unittest.TestCase):
    def test_normalize_duid_accepts_compact_and_colon_separated_values(self):
        expected = "0004aabbccdd"
        self.assertEqual(normalize_duid(expected), expected)
        self.assertEqual(normalize_duid("00:04:AA:BB:CC:DD"), expected)

    def test_counter_matches_allocation_events_for_exact_transaction_and_duid(self):
        log_text = """
2026-01-01 INFO [kea-dhcp6.alloc-engine] DHCP6_LEASE_REUSE duid=[00:04:aa:bb], tid=0x06ff20: lease reused
2026-01-01 INFO [kea-dhcp6.alloc-engine] DHCP6_LEASE_ALLOC duid=[00:04:aa:bb], tid=0x6ff20: lease allocated
2026-01-01 INFO [kea-dhcp6.packets] DHCP6_PACKET_RECEIVED duid=[00:04:aa:bb], tid=0x6ff20: REQUEST received
2026-01-01 INFO [kea-dhcp6.alloc-engine] DHCP6_LEASE_REUSE duid=[00:04:aa:bc], tid=0x6ff20: other client
2026-01-01 INFO [kea-dhcp6.alloc-engine] DHCP6_LEASE_REUSE duid=[00:04:aa:bb], tid=0x6ff21: other transaction
"""

        self.assertEqual(count_matching_requests(log_text, 0x6FF20, "0004aabb"), 2)

    def test_counter_ignores_malformed_log_metadata(self):
        log_text = """
DHCP6_LEASE_REUSE duid=[not-a-duid], tid=0x123456: malformed client
DHCP6_LEASE_REUSE duid=[00:04:aa:bb], tid=xyz: malformed transaction
DHCP6_LEASE_REUSE tid=0x123456: missing client
"""

        self.assertEqual(count_matching_requests(log_text, 0x123456, "0004aabb"), 0)


if __name__ == "__main__":
    unittest.main()
