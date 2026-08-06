import os
import tempfile
import unittest

from asa import runner
from asa.finding import Category, Evidence, Finding, Severity
from asa.report.model import MAX_NEED_YOU_ITEMS, build_report_model


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def make_finding(check_id, severity, location, auto_fixable=False, category=Category.SECRETS):
    return Finding(
        check_id=check_id, category=category, severity=severity,
        title=f"Finding for {check_id}", evidence=Evidence(),
        fix="do the thing", fix_time_estimate="2 min", location=location,
        auto_fixable=auto_fixable,
    )


class TestBuildReportModel(unittest.TestCase):
    def _base_coverage(self):
        return {c.value: {"activated": True, "status": "ok", "error": None} for c in Category}

    def _fake_manifest(self):
        with tempfile.TemporaryDirectory() as root:
            pass  # closed dir is fine, only .scan_root/.skipped/.unreadable/.components read
        from asa.manifest import Manifest
        return Manifest(scan_root="/tmp/fake", scanned_at="2026-01-01T00:00:00Z", components=[], skipped=[], unreadable=[], host={})

    def test_need_you_excludes_auto_fixable(self):
        m = self._fake_manifest()
        findings = [
            make_finding("secrets.a", Severity.CRITICAL, "a.env", auto_fixable=False),
            make_finding("secrets.b", Severity.HIGH, "b.env", auto_fixable=True),
        ]
        model = build_report_model(m, findings, self._base_coverage())
        self.assertEqual(len(model.need_you), 1)
        self.assertEqual(model.need_you[0].finding_id, findings[0].id)

    def test_need_you_capped_with_overflow(self):
        m = self._fake_manifest()
        findings = [make_finding(f"secrets.{i}", Severity.CRITICAL, f"f{i}.env") for i in range(10)]
        model = build_report_model(m, findings, self._base_coverage())
        self.assertEqual(len(model.need_you), MAX_NEED_YOU_ITEMS)
        self.assertEqual(model.need_you_overflow, 3)

    def test_pills_needs_you_count_matches_total_not_capped(self):
        m = self._fake_manifest()
        findings = [make_finding(f"secrets.{i}", Severity.CRITICAL, f"f{i}.env") for i in range(10)]
        model = build_report_model(m, findings, self._base_coverage())
        needs_you_pill = next(p for p in model.pills if p.label == "Needs You")
        self.assertEqual(needs_you_pill.count, 10)

    def test_to_rotate_pill_counts_rotate_relevant_checks(self):
        m = self._fake_manifest()
        findings = [
            make_finding("secrets.hardcoded_value_instead_of_env_ref", Severity.HIGH, "a"),
            make_finding("secrets.dotenv_world_readable", Severity.HIGH, "b", auto_fixable=True),
        ]
        model = build_report_model(m, findings, self._base_coverage())
        to_rotate_pill = next(p for p in model.pills if p.label == "To Rotate")
        self.assertEqual(to_rotate_pill.count, 1)

    def test_clean_categories_detected(self):
        m = self._fake_manifest()
        coverage = self._base_coverage()
        model = build_report_model(m, [], coverage)
        clean_pill = next(p for p in model.pills if p.label == "Clean")
        self.assertEqual(clean_pill.count, len(Category))

    def test_detail_sections_cover_every_category_even_with_zero_findings(self):
        m = self._fake_manifest()
        model = build_report_model(m, [], self._base_coverage())
        self.assertEqual({s.category for s in model.detail_sections}, {c.value for c in Category})

    def test_errored_category_reflected_in_coverage_summary(self):
        m = self._fake_manifest()
        coverage = self._base_coverage()
        coverage["network"] = {"activated": True, "status": "error", "error": "boom"}
        model = build_report_model(m, [], coverage)
        self.assertIn("network", model.coverage_summary)

    def test_fixed_count_passthrough(self):
        m = self._fake_manifest()
        model = build_report_model(m, [], self._base_coverage(), fixed_count=3)
        fixed_pill = next(p for p in model.pills if p.label == "Fixed")
        self.assertEqual(fixed_pill.count, 3)


class TestFixGuidanceNeverMissing(unittest.TestCase):
    """Deliberate substitute for the plan's FIX_NEXT_STEP_TEMPLATES table:
    every Finding emitted by every registered checker must carry a
    non-empty fix and fix_time_estimate, so a NeedYouItem never renders a
    vague/blank next step. A new check that forgets to set these fails
    here immediately."""

    def test_all_secrets_findings_have_fix_guidance(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            write(os.path.join(root, "app.py"), 'KEY = "AIza' + "q" * 35 + '"\n')
            path = os.path.join(root, ".env")
            write(path, "PASSWORD=someactualvalue123456\n")
            os.chmod(path, 0o644)
            write(os.path.join(root, "sub", ".env"), "PASSWORD=someactualvalue123456\n")

            m, findings, coverage = runner.run(root)
            self.assertGreater(len(findings), 0, "fixture should have produced findings to check")
            for f in findings:
                if f.check_id.endswith(".checker_error"):
                    continue  # error findings have their own fixed guidance text, exempt
                self.assertTrue(f.fix, f"{f.check_id} has empty fix text")
                self.assertTrue(f.fix_time_estimate, f"{f.check_id} has no fix_time_estimate")


if __name__ == "__main__":
    unittest.main()
