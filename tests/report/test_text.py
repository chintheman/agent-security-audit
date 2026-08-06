import unittest

from asa.report import model as model_mod
from asa.report.text import render_text


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
        fixed_or_clean=[model_mod.CleanItem(kind="clean_category", label="network: no findings")],
        detail_sections=[model_mod.DetailSection(category="secrets", label="Secrets", findings=detail_findings)],
        coverage_summary="1 component detected, 0 skipped, 0 unaccounted",
    )


class TestTerminalRenderer(unittest.TestCase):
    def test_pill_line_present(self):
        m = make_model()
        out = render_text(m, fmt="term")
        self.assertIn("Needs You: 0", out)

    def test_need_you_item_rendered(self):
        item = model_mod.NeedYouItem(finding_id="x", title="A very specific title", next_step="do the fix", time_estimate="5 min", severity="High", location="a.env")
        m = make_model(need_you=[item])
        out = render_text(m, fmt="term")
        self.assertIn("A very specific title", out)
        self.assertIn("do the fix", out)
        self.assertIn("5 min", out)

    def test_detail_hidden_without_verbose(self):
        finding = model_mod.DetailFinding(id="x", check_id="test.x", title="SUPER SECRET DETAIL TITLE", severity="Low", fix="fix it", location="a", evidence={}, confidence="high", source="heuristic", auto_fixable=False)
        m = make_model(detail_findings=[finding])
        out = render_text(m, fmt="term", verbose=False)
        self.assertNotIn("SUPER SECRET DETAIL TITLE", out)

    def test_detail_shown_with_verbose(self):
        finding = model_mod.DetailFinding(id="x", check_id="test.x", title="SUPER SECRET DETAIL TITLE", severity="Low", fix="fix it", location="a", evidence={}, confidence="high", source="heuristic", auto_fixable=False)
        m = make_model(detail_findings=[finding])
        out = render_text(m, fmt="term", verbose=True)
        self.assertIn("SUPER SECRET DETAIL TITLE", out)

    def test_no_findings_message(self):
        m = make_model()
        out = render_text(m, fmt="term")
        self.assertIn("nothing", out.lower())


class TestMarkdownRenderer(unittest.TestCase):
    def test_uses_details_summary(self):
        m = make_model()
        out = render_text(m, fmt="md")
        self.assertIn("<details>", out)
        self.assertIn("<summary>", out)

    def test_detail_always_included_in_markdown(self):
        # markdown's <details> is natively collapsible in the renderer
        # (GitHub etc.), so unlike the terminal renderer it doesn't need a
        # separate verbose flag to decide whether to include the content.
        finding = model_mod.DetailFinding(id="x", check_id="test.x", title="MARKDOWN DETAIL TITLE", severity="Low", fix="fix it", location="a", evidence={}, confidence="high", source="heuristic", auto_fixable=False)
        m = make_model(detail_findings=[finding])
        out = render_text(m, fmt="md")
        self.assertIn("MARKDOWN DETAIL TITLE", out)

    def test_ai_assisted_source_noted(self):
        finding = model_mod.DetailFinding(id="x", check_id="test.x", title="AI Finding", severity="Medium", fix="fix it", location="a", evidence={}, confidence="medium", source="ai-assist", auto_fixable=False)
        m = make_model(detail_findings=[finding])
        out = render_text(m, fmt="md")
        self.assertIn("ai-assist", out)


if __name__ == "__main__":
    unittest.main()
