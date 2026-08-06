import os
import tempfile
import unittest
from unittest import mock

from asa import runner


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


class TestRunnerHappyPath(unittest.TestCase):
    def test_returns_manifest_findings_coverage(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            m, findings, coverage = runner.run(root)
            self.assertEqual(m.scan_root, os.path.abspath(root))
            self.assertTrue(any(f.check_id == "secrets.hardcoded_value_instead_of_env_ref" for f in findings))
            self.assertIn("secrets", coverage)
            self.assertEqual(coverage["secrets"]["status"], "ok")

    def test_clean_target_has_ok_coverage_and_no_findings(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hello\n")
            m, findings, coverage = runner.run(root)
            self.assertEqual(findings, [])
            self.assertEqual(coverage["secrets"]["status"], "ok")

    def test_category_filter(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hello\n")
            m, findings, coverage = runner.run(root, categories=["network"])
            self.assertNotIn("secrets", coverage)


class TestRunnerFindingsAreDeduped(unittest.TestCase):
    def test_no_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            m, findings, coverage = runner.run(root)
            ids = [f.id for f in findings]
            self.assertEqual(len(ids), len(set(ids)))


class TestRunnerFindingsAreSorted(unittest.TestCase):
    def test_severity_first_ordering(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o644)
            m, findings, coverage = runner.run(root)
            severities = [f.severity.value for f in findings]
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            self.assertEqual(severities, sorted(severities, key=lambda s: order[s]))


class TestRunnerSurvivesABrokenChecker(unittest.TestCase):
    def test_activates_exception_does_not_crash_scan(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hello\n")
            with mock.patch("asa.checkers.secrets.activates", side_effect=RuntimeError("boom")):
                m, findings, coverage = runner.run(root)
            self.assertEqual(coverage["secrets"]["status"], "error")
            self.assertTrue(any(f.check_id == "secrets.checker_error" for f in findings))

    def test_run_exception_does_not_crash_scan(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hello\n")
            with mock.patch("asa.checkers.secrets.run", side_effect=RuntimeError("boom")):
                m, findings, coverage = runner.run(root)
            self.assertEqual(coverage["secrets"]["status"], "error")
            self.assertTrue(any(f.check_id == "secrets.checker_error" for f in findings))
            # the error finding itself must never leak the exception's
            # str() blindly if it happened to contain something sensitive --
            # here we just check the scan didn't raise and produced a
            # well-formed, serializable finding
            err = next(f for f in findings if f.check_id == "secrets.checker_error")
            self.assertEqual(err.severity.value, "info")
            self.assertIsInstance(err.to_dict(), dict)


if __name__ == "__main__":
    unittest.main()
