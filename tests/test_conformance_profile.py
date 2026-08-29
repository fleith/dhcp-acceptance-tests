import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "docs" / "conformance-profile.json"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RESERVED_IID_TOPOLOGY = ROOT / "docker-compose.ipv6-reserved-iid.yml"
CAPACITY_TOPOLOGY = ROOT / "docker-compose.capacity.yml"
CAPACITY_RUNNER = ROOT / "run_capacity_tests.sh"


class ConformanceProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = json.loads(PROFILE.read_text(encoding="utf-8"))

    def test_profile_has_unique_well_formed_rows(self):
        rows = self.profile["coverage"]
        ids = [row["id"] for row in rows]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(identifier.startswith("GAP-") for identifier in ids))
        for row in rows:
            self.assertIn(row["status"], {"covered", "conditional", "partial"})
            self.assertIn(
                row["mode"],
                {"required", "focused", "orchestrated", "capability", "documentation"},
            )
            self.assertTrue(row["title"])
            self.assertTrue(row["evidence"])

    def test_all_evidence_files_exist(self):
        for row in self.profile["coverage"]:
            for relative_path in row["evidence"]:
                self.assertTrue(
                    (ROOT / relative_path).is_file(),
                    f"{row['id']} refers to missing evidence {relative_path}",
                )

    def test_feature_tags_are_backed_by_evidence(self):
        for row in self.profile["coverage"]:
            evidence_text = "\n".join(
                (ROOT / path).read_text(encoding="utf-8")
                for path in row["evidence"]
            )
            for tag in row["tags"]:
                self.assertIn(tag, evidence_text, f"{row['id']} has unbacked tag {tag}")

    def test_every_original_qualification_area_is_indexed(self):
        required_ids = {
            "GAP-PERSISTENCE",
            "GAP-IDEMPOTENCY",
            "GAP-SERVER-PING-CHECK",
            "GAP-CONCURRENCY",
            "GAP-V4-RELAY",
            "GAP-POLICY",
            "GAP-CONFIG-SAFETY",
            "GAP-OVERLAP-LEASE-SELECTION",
            "GAP-RELOAD",
            "GAP-MALFORMED",
            "GAP-CAPACITY",
            "GAP-CRASH-CONSISTENCY",
            "GAP-RUNTIME-STORAGE",
            "GAP-HA",
            "GAP-DDNS",
            "GAP-AUTH-RECONFIGURE",
            "GAP-RFC-TRACEABILITY",
        }
        actual_ids = {row["id"] for row in self.profile["coverage"]}
        self.assertTrue(required_ids <= actual_ids)

    def test_reserved_iid_profile_runs_on_supported_kea_versions(self):
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        start = workflow.index("  dhcpv6-reserved-iid-pools:")
        end = workflow.index("\n  focused-robustness:", start)
        job = workflow[start:end]
        self.assertIn("run_dhcpv6_reserved_iid_tests.sh", job)
        self.assertIn("run_dhcpv6_request_regeneration_tests.sh", job)
        self.assertIn("run_dhcpv6_rebind_ownership_tests.sh", job)
        self.assertIn("server_version: kea-lts", job)
        self.assertIn("server_version: kea-stable", job)
        self.assertIn("docker-compose.ipv6-reserved-iid.yml down -v", job)
        self.assertIn("docker-compose.ipv6-request-observability.yml down -v", job)

    def test_reserved_iid_topology_covers_registry_boundaries(self):
        topology = RESERVED_IID_TOPOLOGY.read_text(encoding="utf-8").lower()
        forbidden_start = topology.index("test_dhcpv6_reserved_pool_forbidden")
        allowed_start = topology.index("test_dhcpv6_reserved_pool_allowed")
        allowed = topology[allowed_start:forbidden_start]
        forbidden = topology[forbidden_start:]
        self.assertNotIn("200:5eff:fe00:5214", allowed)
        for candidate in (
            "fd00:29::",
            "200:5eff:fe00:0",
            "200:5eff:fe00:2909",
            "200:5eff:fe00:5212",
            "200:5eff:fe00:5213",
            "200:5eff:fe00:5214",
            "200:5eff:fe80:0",
            "200:5eff:feff:ffff",
            "fdff:ffff:ffff:ff80",
            "fdff:ffff:ffff:ffbf",
            "fdff:ffff:ffff:ffff",
        ):
            self.assertIn(candidate, forbidden)

    def test_focused_robustness_runs_both_ip_families(self):
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        start = workflow.index("  focused-robustness:")
        end = workflow.index("\n  runtime-storage-fault:", start)
        job = workflow[start:end]
        self.assertIn("ip_version: [v4, v6]", job)
        self.assertIn("--ip-version ${{ matrix.ip_version }}", job)
        self.assertIn("--tags @focused_robustness", job)

        malformed = next(
            row for row in self.profile["coverage"] if row["id"] == "GAP-MALFORMED"
        )
        self.assertEqual(malformed["status"], "covered")
        self.assertIn("features/dhcpv6_malformed_corpus.feature", malformed["evidence"])

    def test_capacity_profile_has_smoke_scheduled_and_endurance_execution(self):
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        runner = CAPACITY_RUNNER.read_text(encoding="utf-8")
        topology = CAPACITY_TOPOLOGY.read_text(encoding="utf-8")
        capacity = next(
            row for row in self.profile["coverage"] if row["id"] == "GAP-CAPACITY"
        )

        self.assertEqual(capacity["status"], "covered")
        self.assertEqual(capacity["mode"], "orchestrated")
        self.assertIn("features/dhcpv4_capacity.feature", capacity["evidence"])
        self.assertIn("dhcpv4-capacity-smoke:", workflow)
        self.assertIn("dhcpv4-capacity-scheduled:", workflow)
        self.assertIn("dhcpv4-capacity-endurance:", workflow)
        self.assertIn("TEST_DHCPV4_CAPACITY_POOL_SIZE=256", runner)
        self.assertIn("TEST_DHCPV4_CAPACITY_POOL_SIZE=1024", runner)
        self.assertIn("  endurance)", runner)
        self.assertIn("TEST_DHCPV4_CAPACITY_DURATION_SECONDS", runner)
        self.assertIn("subnet: 172.29.0.0/20", topology)

    def test_rfc_traceability_profile_is_complete(self):
        traceability = next(
            row
            for row in self.profile["coverage"]
            if row["id"] == "GAP-RFC-TRACEABILITY"
        )
        self.assertEqual(traceability["status"], "covered")


if __name__ == "__main__":
    unittest.main()
