import csv
import re
import unittest
from pathlib import Path

from render_rfc_requirements import render_matrix


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "rfc-requirements.csv"
DOCUMENT = ROOT / "docs" / "RFC_REQUIREMENTS.md"
EXPECTED_RFCS = {
    "2131", "2132", "3011", "3046", "3396", "3442",
    "4361", "4702", "4704", "6842", "8925", "9915",
}


class RfcRequirementsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with MATRIX.open(newline="", encoding="utf-8") as matrix_file:
            cls.rows = list(csv.DictReader(matrix_file))

    def test_matrix_has_expected_schema_and_unique_ids(self):
        expected_fields = {
            "requirement_id", "rfc", "section", "level", "role",
            "status", "requirement", "evidence", "notes",
        }
        self.assertTrue(self.rows)
        self.assertEqual(set(self.rows[0]), expected_fields)
        ids = [row["requirement_id"] for row in self.rows]
        self.assertEqual(len(ids), len(set(ids)))
        for row in self.rows:
            self.assertRegex(row["requirement_id"], r"^RFC\d+-[A-Z0-9.-]+$")
            self.assertIn(row["level"], {"MUST", "MUST NOT", "SHOULD", "SHOULD NOT"})
            self.assertEqual(row["role"], "server")
            self.assertIn(row["status"], {"covered", "partial", "conditional", "gap", "excluded"})
            self.assertTrue(row["section"])
            self.assertTrue(row["requirement"])

    def test_all_claimed_rfcs_are_indexed(self):
        self.assertEqual({row["rfc"] for row in self.rows}, EXPECTED_RFCS)

    def test_evidence_names_real_feature_scenarios(self):
        for row in self.rows:
            if row["status"] in {"covered", "partial", "conditional"}:
                self.assertTrue(row["evidence"], f"{row['requirement_id']} needs evidence")
            if row["status"] in {"gap", "excluded"}:
                self.assertTrue(row["notes"], f"{row['requirement_id']} needs rationale")
            for item in filter(None, row["evidence"].split(";")):
                path, scenario = item.split("::", 1)
                feature = ROOT / path
                self.assertTrue(feature.is_file(), f"Missing evidence file {path}")
                text = feature.read_text(encoding="utf-8")
                pattern = rf"^\s*Scenario(?: Outline)?:\s*{re.escape(scenario)}\s*$"
                self.assertRegex(text, re.compile(pattern, re.MULTILINE), f"Missing scenario {scenario}")

    def test_rendered_document_is_current(self):
        self.assertEqual(DOCUMENT.read_text(encoding="utf-8"), render_matrix())


if __name__ == "__main__":
    unittest.main()
