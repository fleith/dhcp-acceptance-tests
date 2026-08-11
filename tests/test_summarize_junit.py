import tempfile
from pathlib import Path
import unittest

from summarize_junit import classify_failures, classify_runtime_failure, read_reports


REPORT = """\
<testsuite name="compatibility" tests="3" failures="2" errors="0" skipped="0">
  <testcase classname="dhcp_rfc8925_ipv6_only_preferred" name="known Kea behavior">
    <failure message="No DHCPOFFER">expected difference</failure>
  </testcase>
  <testcase classname="dhcpv6_relay" name="unrelated regression">
    <failure message="No RELAY-REPLY">unexpected failure</failure>
  </testcase>
  <testcase classname="dhcp_lease" name="passing scenario" />
</testsuite>
"""


class SummarizeJunitTests(unittest.TestCase):
    def test_expected_pattern_does_not_mask_unrelated_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "TESTS-compatibility.xml"
            report.write_text(REPORT, encoding="utf-8")

            files, totals, failures = read_reports(Path(directory))
            expected, unexpected = classify_failures(
                failures, ["dhcp_rfc8925_ipv6_only_preferred"]
            )

        self.assertEqual(len(files), 1)
        self.assertEqual(totals["tests"], 3)
        self.assertEqual(totals["failures"], 2)
        self.assertEqual([item["name"] for item in expected], ["known Kea behavior"])
        self.assertEqual(
            [item["name"] for item in unexpected], ["unrelated regression"]
        )

    def test_no_pattern_keeps_every_failure_unexpected(self):
        failures = [
            {"name": "failure", "source": "report.xml", "detail": "known path"}
        ]

        expected, unexpected = classify_failures(failures, [])

        self.assertEqual(expected, [])
        self.assertEqual(unexpected, failures)

    def test_expected_runtime_signature_classifies_missing_junit_failure(self):
        expected, unexpected = classify_runtime_failure(
            "failure",
            [],
            "Assertion in /usr/include/c++/bits/stl_vector.h failed",
            ["stl_vector.h"],
        )

        self.assertEqual(expected, ["stl_vector.h"])
        self.assertEqual(unexpected, [])

    def test_missing_runtime_signature_keeps_infrastructure_failure_unexpected(self):
        expected, unexpected = classify_runtime_failure(
            "failure",
            [],
            "docker pull failed",
            ["stl_vector.h"],
        )

        self.assertEqual(expected, [])
        self.assertEqual(unexpected, ["stl_vector.h"])

    def test_failed_run_without_junit_or_runtime_signature_is_unexpected(self):
        expected, unexpected = classify_runtime_failure(
            "failure", [], "", []
        )

        self.assertEqual(expected, [])
        self.assertEqual(unexpected, ["no classified JUnit scenario failure"])


if __name__ == "__main__":
    unittest.main()
