#!/usr/bin/env python3
"""Whole-pipeline smoke test, distinct from the per-checker unit tests --
runs the actual `asa` CLI against tests/fixtures/{clean_project,
selftest_project} and diffs the result against
tests/fixtures/expected_summary.json. Catches integration-level
regressions (e.g. registry wiring silently dropping a checker) that
per-module unit tests wouldn't, since it exercises the full manifest ->
checkers -> report path exactly the way a real user would.

Usage: python3 scripts/run_selftest.py
Exit 0 on match, 1 on mismatch (with a diff printed), 2 on a setup error.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = os.path.join(REPO_ROOT, "tests", "fixtures")
EXPECTED_PATH = os.path.join(FIXTURES_DIR, "expected_summary.json")


def run_scan(fixture_name: str) -> dict:
    fixture_path = os.path.join(FIXTURES_DIR, fixture_name)
    proc = subprocess.run(
        [sys.executable, "-m", "asa", "scan", fixture_path, "--format", "json"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    out_dir = os.path.join(fixture_path, "asa-output")
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)  # never leave scan artifacts in a checked-in fixture
    if proc.returncode not in (0, 1):  # 0=clean, 1=findings present -- both are valid outcomes here
        print(f"FAIL [{fixture_name}]: unexpected exit code {proc.returncode}\nstderr:\n{proc.stderr}")
        sys.exit(2)
    try:
        return json.loads(proc.stdout)
    except ValueError as exc:
        print(f"FAIL [{fixture_name}]: stdout was not valid JSON: {exc}\nstdout:\n{proc.stdout[:2000]}")
        sys.exit(2)


def check_clean_project(expected: dict) -> list:
    data = run_scan("clean_project")
    total = sum(len(s["findings"]) for s in data["detail_sections"])
    problems = []
    if total > expected["max_total_findings"]:
        problems.append(f"clean_project: expected <= {expected['max_total_findings']} findings, got {total}")
    return problems


def check_selftest_project(expected: dict) -> list:
    data = run_scan("selftest_project")
    all_findings = [f for s in data["detail_sections"] for f in s["findings"]]
    total = len(all_findings)
    found_check_ids = {f["check_id"] for f in all_findings}
    problems = []
    if total < expected["min_total_findings"]:
        problems.append(f"selftest_project: expected >= {expected['min_total_findings']} findings, got {total}")
    missing = set(expected["must_include_check_ids"]) - found_check_ids
    if missing:
        problems.append(f"selftest_project: missing expected check_id(s): {sorted(missing)}")
    return problems


def main() -> int:
    with open(EXPECTED_PATH, "r", encoding="utf-8") as fh:
        expected = json.load(fh)

    problems = []
    problems += check_clean_project(expected["clean_project"])
    problems += check_selftest_project(expected["selftest_project"])

    if problems:
        print("Selftest FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1

    print("Selftest passed: clean_project stayed clean, selftest_project produced every expected finding type.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
