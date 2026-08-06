import re
import unittest

from asa.report import model as model_mod
from asa.report.html import render_html


def make_model(need_you=None, detail_findings=None):
    need_you = need_you or []
    detail_findings = detail_findings or []
    return model_mod.ReportModel(
        scanned_target="/tmp/example",
        scanned_at="2026-01-01T00:00:00Z",
        tool_version="0.1.0",
        pills=[model_mod.Pill(label="Needs You", count=len(need_you), tone="critical" if need_you else "good")],
        need_you=need_you,
        need_you_overflow=0,
        fixed_or_clean=[],
        detail_sections=[model_mod.DetailSection(category="secrets", label="Secrets", findings=detail_findings)],
        coverage_summary="1 component detected, 0 skipped, 0 unaccounted",
    )


class TestHtmlRenderer(unittest.TestCase):
    def test_produces_valid_looking_document(self):
        out = render_html(make_model())
        self.assertTrue(out.strip().startswith("<!doctype html>"))
        self.assertIn("<html", out)
        self.assertIn("</html>", out)

    def test_css_inlined_not_linked(self):
        out = render_html(make_model())
        self.assertIn("<style>", out)
        self.assertNotIn('<link rel="stylesheet"', out)

    def test_no_external_network_references(self):
        out = render_html(make_model())
        for forbidden in ("http://", "https://", "cdn.", "//fonts.googleapis"):
            self.assertNotIn(forbidden, out)

    def test_html_special_characters_are_escaped(self):
        finding = model_mod.DetailFinding(
            id="x", check_id="test.x", title='<script>alert(1)</script>', severity="High",
            fix="fix it", location='"; DROP TABLE x; --', evidence={},
            confidence="high", source="heuristic", auto_fixable=False,
        )
        m = make_model(detail_findings=[finding])
        out = render_html(m)
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_need_you_item_rendered(self):
        item = model_mod.NeedYouItem(finding_id="x", title="A distinctive title", next_step="do the fix", time_estimate="5 min", severity="High", location="a.env")
        m = make_model(need_you=[item])
        out = render_html(m)
        self.assertIn("A distinctive title", out)
        self.assertIn("do the fix", out)

    def test_pill_counts_rendered(self):
        out = render_html(make_model())
        self.assertIn("Needs You", out)

    def test_self_contained_single_file(self):
        # exactly one <html> document, no iframes/external script src
        out = render_html(make_model())
        self.assertEqual(len(re.findall(r"<script\s+src=", out)), 0)


if __name__ == "__main__":
    unittest.main()
