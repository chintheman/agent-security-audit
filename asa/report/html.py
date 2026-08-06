"""Self-contained single-file HTML renderer. CSS/JS are inlined from
report/assets/ at render time (read via a plain file path relative to this
module -- avoids importlib.resources API differences across the 3.9-3.12
support matrix). No CDN links, no external requests of any kind -- this
tool's "never makes an outbound call" invariant extends to viewing its own
report.

Every piece of text is run through html.escape() before insertion --
Finding fields (titles, locations, evidence snippets) come from scanned
target content, which is untrusted input as far as HTML injection goes,
even though it's already secret-redacted by asa/redact.py before it ever
reaches this renderer.
"""

from __future__ import annotations

import os
from html import escape as e

_ASSET_DIR = os.path.join(os.path.dirname(__file__), "assets")


def _asset(name: str) -> str:
    with open(os.path.join(_ASSET_DIR, name), "r", encoding="utf-8") as fh:
        return fh.read()


def _pill_html(model) -> str:
    out = []
    for p in model.pills:
        tone = "good" if p.tone == "good" else ("crit" if p.tone == "critical" else "high" if p.tone == "high" else "")
        out.append(f'<span class="pill {tone}">{e(p.label)}: <b>{p.count}</b></span>')
    return "\n".join(out)


def _need_you_html(model) -> str:
    if not model.need_you:
        return '<div class="cd">Nothing -- no critical/high findings requiring a manual decision.</div>'
    out = []
    for item in model.need_you:
        out.append(
            f'<div class="card">'
            f'<div class="ct">[{e(item.severity)}] {e(item.title)}</div>'
            f'<div class="cd">&rarr; {e(item.next_step)} <span class="badge">{e(item.time_estimate)}</span></div>'
            f'<div class="cd">at <code>{e(item.location)}</code></div>'
            f'</div>'
        )
    if model.need_you_overflow:
        out.append(f'<div class="cd">+{model.need_you_overflow} more, see detail below</div>')
    return "\n".join(out)


def _clean_html(model) -> str:
    out = []
    for item in model.fixed_or_clean:
        suffix = f" -- {e(item.detail)}" if item.detail else ""
        out.append(f'<div class="finding"><span class="t">{e(item.label)}</span><span class="f">{suffix}</span></div>')
    return "\n".join(out) if out else '<div class="cd">Nothing here.</div>'


def _detail_html(model) -> str:
    out = []
    for section in model.detail_sections:
        status_note = "" if section.status == "ok" else f' <span class="badge">checker status: {e(section.status)}</span>'
        rows = []
        for f in section.findings:
            source_note = f' <span class="badge">{e(f.source)}, confidence={e(f.confidence)}</span>' if f.source != "heuristic" else ""
            rows.append(
                f'<div class="finding">'
                f'<div class="t">[{e(f.severity)}] {e(f.title)}{source_note}</div>'
                f'<div class="f">Fix: {e(f.fix)}</div>'
                f'<div class="f">Location: <code>{e(f.location)}</code></div>'
                f'</div>'
            )
        rows_html = "\n".join(rows) if rows else '<div class="finding"><span class="f">No findings.</span></div>'
        out.append(
            f'<details><summary>{e(section.label)} ({len(section.findings)}){status_note}</summary>'
            f'<div class="body">{rows_html}</div></details>'
        )
    return "\n".join(out)


def render_html(model) -> str:
    css = _asset("report.css")
    js = _asset("report.js")
    ai_block = f'<h2>AI-assist</h2><div class="cd">{e(model.ai_assist_summary)}</div>' if model.ai_assist_summary else ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Audit -- {e(model.scanned_target)}</title>
<style>{css}</style>
</head>
<body>
<div class="wrap">
  <h1>Security Audit</h1>
  <p class="sub">{e(model.scanned_target)} &middot; scanned {e(model.scanned_at)} &middot; asa v{e(model.tool_version)}</p>

  <div class="bar">{_pill_html(model)}</div>

  <h2>Need You</h2>
  {_need_you_html(model)}

  <h2>Coverage</h2>
  <div class="cd">{e(model.coverage_summary)}</div>

  {ai_block}

  <details>
    <summary>Clean / lower-priority ({len(model.fixed_or_clean)})</summary>
    <div class="body">{_clean_html(model)}</div>
  </details>

  <h2>Detail by category</h2>
  {_detail_html(model)}
</div>
<script>{js}</script>
</body>
</html>
"""
