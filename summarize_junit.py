#!/usr/bin/env python3
"""Summarize Behave JUnit reports for GitHub Actions."""

import argparse
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", default="test-results")
    parser.add_argument("--title", default="DHCP acceptance tests")
    parser.add_argument("--summary-file")
    parser.add_argument("--run-outcome", choices=("success", "failure", "cancelled"))
    parser.add_argument("--expected-failure-pattern", action="append", default=[])
    return parser.parse_args()


def integer_attr(element, name):
    try:
        return int(element.attrib.get(name, "0"))
    except ValueError:
        return 0


def suite_elements(root):
    if root.tag == "testsuite":
        return [root]
    return list(root.findall(".//testsuite"))


def failure_record(path, suite, case, failure):
    searchable = " ".join(
        value
        for value in (
            path.name,
            suite.attrib.get("name", ""),
            suite.attrib.get("classname", ""),
            case.attrib.get("name", ""),
            case.attrib.get("classname", ""),
            failure.attrib.get("message", ""),
            failure.text or "",
        )
        if value
    )
    return {
        "name": case.attrib.get("name", "unnamed scenario"),
        "source": path.name,
        "detail": " ".join(searchable.split()),
    }


def read_reports(results_dir):
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    failures = []
    files = sorted(results_dir.rglob("*.xml")) if results_dir.exists() else []

    for path in files:
        root = ET.parse(path).getroot()
        for suite in suite_elements(root):
            totals["tests"] += integer_attr(suite, "tests")
            totals["failures"] += integer_attr(suite, "failures")
            totals["errors"] += integer_attr(suite, "errors")
            totals["skipped"] += integer_attr(suite, "skipped")
            for case in suite.findall(".//testcase"):
                for failure in list(case.findall("failure")) + list(case.findall("error")):
                    failures.append(failure_record(path, suite, case, failure))

    return files, totals, failures


def classify_failures(failures, patterns):
    normalized = [pattern.lower() for pattern in patterns if pattern]
    expected = []
    unexpected = []
    for failure in failures:
        if normalized and any(pattern in failure["detail"].lower() for pattern in normalized):
            expected.append(failure)
        else:
            unexpected.append(failure)
    return expected, unexpected


def markdown(args, files, totals, expected, unexpected):
    passed = max(
        totals["tests"] - totals["failures"] - totals["errors"] - totals["skipped"],
        0,
    )
    lines = [
        f"### {args.title}",
        "",
        "| Passed | Failed | Errors | Skipped | Reports |",
        "| ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {passed} | {totals['failures']} | {totals['errors']} | "
            f"{totals['skipped']} | {len(files)} |"
        ),
    ]

    if expected:
        lines.extend(["", "**Expected compatibility differences**"])
        lines.extend(f"- `{item['source']}`: {item['name']}" for item in expected)
    if unexpected:
        lines.extend(["", "**Unexpected failures**"])
        lines.extend(f"- `{item['source']}`: {item['name']}" for item in unexpected)
    if not files:
        lines.extend(["", "No JUnit reports were produced."])
    return "\n".join(lines) + "\n"


def emit_annotation(level, title, message):
    if os.getenv("GITHUB_ACTIONS") == "true":
        print(f"::{level} title={title}::{message}")


def main():
    args = parse_args()
    results_dir = Path(args.results)
    files, totals, failures = read_reports(results_dir)
    expected, unexpected = classify_failures(
        failures, args.expected_failure_pattern
    )
    report = markdown(args, files, totals, expected, unexpected)
    print(report, end="")

    summary_file = args.summary_file or os.getenv("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(report)

    for item in expected:
        emit_annotation("warning", "Expected compatibility difference", item["name"])
    for item in unexpected:
        emit_annotation("error", "Unexpected DHCP test failure", item["name"])

    if unexpected:
        return 1
    if args.run_outcome in ("failure", "cancelled") and not failures:
        emit_annotation(
            "error",
            "DHCP test infrastructure failure",
            "The test command failed without a classified JUnit scenario failure.",
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
