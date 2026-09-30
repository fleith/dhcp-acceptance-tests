import tempfile
from pathlib import Path
import unittest

from summarize_junit import (
    RUN_STATUS_FILE,
    classify_failures,
    classify_runtime_failure,
    incomplete_run_problems,
    read_reports,
)


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
    def test_expected_scenario_does_not_mask_unrelated_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "TESTS-compatibility.xml"
            report.write_text(REPORT, encoding="utf-8")

            files, totals, failures = read_reports(Path(directory))
            expected, unexpected = classify_failures(failures, ["known Kea behavior"])

        self.assertEqual(len(files), 1)
        self.assertEqual(totals["tests"], 3)
        self.assertEqual(totals["failures"], 2)
        self.assertEqual([item["name"] for item in expected], ["known Kea behavior"])
        self.assertEqual(
            [item["name"] for item in unexpected], ["unrelated regression"]
        )

    def test_feature_or_file_name_does_not_mark_failures_expected(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "TESTS-dhcp_rfc8925_ipv6_only_preferred.xml"
            report.write_text(REPORT, encoding="utf-8")
            _, _, failures = read_reports(Path(directory))

        expected, unexpected = classify_failures(
            failures, ["dhcp_rfc8925_ipv6_only_preferred"]
        )

        self.assertEqual(expected, [])
        self.assertEqual(len(unexpected), 2)

    def test_run_that_never_finished_is_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            finished = Path(directory) / "finished"
            crashed = Path(directory) / "crashed"
            for path, status in ((finished, "1"), (crashed, "running")):
                path.mkdir()
                (path / "TESTS-compatibility.xml").write_text(REPORT, encoding="utf-8")
                (path / RUN_STATUS_FILE).write_text(status + "\n", encoding="utf-8")
            _, totals, _ = read_reports(Path(directory))

            problems = incomplete_run_problems(Path(directory), totals)

        self.assertEqual(problems, [f"behave did not finish in {crashed}"])

    def test_run_with_only_skipped_scenarios_is_incomplete(self):
        totals = {"tests": 4, "failures": 0, "errors": 0, "skipped": 4}

        with tempfile.TemporaryDirectory() as directory:
            problems = incomplete_run_problems(Path(directory), totals)

        self.assertEqual(problems, ["no scenario was executed"])

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
