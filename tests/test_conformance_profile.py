import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "docs" / "conformance-profile.json"


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


if __name__ == "__main__":
    unittest.main()
