"""Terminal and Markdown renderers for a ReportModel. Redaction already
happened at the Finding level (asa/redact.py) -- these renderers never
touch a raw value, they only format fields that were already safe when the
Finding was constructed.
"""

from __future__ import annotations


def render_text(model, *, fmt: str = "term", verbose: bool = False) -> str:
    if fmt == "md":
        return _render_markdown(model)
    return _render_terminal(model, verbose=verbose)


def _pill_line(model) -> str:
    return "  ".join(f"[{p.label}: {p.count}]" for p in model.pills)


def _render_terminal(model, *, verbose: bool) -> str:
    lines = []
    lines.append(f"Security Audit -- {model.scanned_target}")
    lines.append(f"Scanned: {model.scanned_at}  |  asa v{model.tool_version}")
    lines.append("")
    lines.append(_pill_line(model))
    lines.append("")

    if model.need_you:
        lines.append(f"NEED YOU ({len(model.need_you)}{f'+{model.need_you_overflow} more' if model.need_you_overflow else ''}):")
        for i, item in enumerate(model.need_you, start=1):
            lines.append(f"  {i}. [{item.severity}] {item.title}")
            lines.append(f"     -> {item.next_step}  ({item.time_estimate})")
            lines.append(f"     at {item.location}")
        lines.append("")
    else:
        lines.append("NEED YOU: nothing -- no critical/high findings requiring a manual decision.")
        lines.append("")

    if model.coverage_summary:
        lines.append(f"Coverage: {model.coverage_summary}")
        lines.append("")

    if model.ai_assist_summary:
        lines.append(f"AI-assist: {model.ai_assist_summary}")
        lines.append("")

    clean_count = len(model.fixed_or_clean)
    if clean_count:
        lines.append(f"Clean / lower-priority ({clean_count}){'':s}" + ("" if verbose else " -- pass --verbose to expand:"))
        if verbose:
            for item in model.fixed_or_clean:
                suffix = f" -- {item.detail}" if item.detail else ""
                lines.append(f"  - {item.label}{suffix}")
        lines.append("")

    if verbose:
        lines.append("DETAIL BY CATEGORY:")
        for section in model.detail_sections:
            status_note = "" if section.status == "ok" else f"  [checker status: {section.status}]"
            lines.append(f"  {section.label} ({len(section.findings)}){status_note}")
            for f in section.findings:
                lines.append(f"    [{f.severity}] {f.title}")
                lines.append(f"      fix: {f.fix}")
                lines.append(f"      at: {f.location}")
                if f.source != "heuristic":
                    lines.append(f"      [{f.source}, confidence={f.confidence}]")
        lines.append("")
    else:
        lines.append("(pass --verbose for full per-category detail)")

    return "\n".join(lines)


def _render_markdown(model) -> str:
    lines = []
    lines.append(f"# Security Audit -- `{model.scanned_target}`")
    lines.append("")
    lines.append(f"Scanned {model.scanned_at} &middot; asa v{model.tool_version}")
    lines.append("")
    lines.append(" ".join(f"`{p.label}: {p.count}`" for p in model.pills))
    lines.append("")

    lines.append("## Need You")
    lines.append("")
    if model.need_you:
        for item in model.need_you:
            lines.append(f"- **[{item.severity}] {item.title}**")
            lines.append(f"  - Next step: {item.next_step} ({item.time_estimate})")
            lines.append(f"  - Location: `{item.location}`")
        if model.need_you_overflow:
            lines.append(f"- *+{model.need_you_overflow} more, see detail below*")
    else:
        lines.append("Nothing -- no critical/high findings requiring a manual decision.")
    lines.append("")

    lines.append(f"**Coverage:** {model.coverage_summary}")
    lines.append("")
    if model.ai_assist_summary:
        lines.append(f"**AI-assist:** {model.ai_assist_summary}")
        lines.append("")

    lines.append("<details>")
    lines.append(f"<summary>Clean / lower-priority ({len(model.fixed_or_clean)})</summary>")
    lines.append("")
    for item in model.fixed_or_clean:
        suffix = f" -- {item.detail}" if item.detail else ""
        lines.append(f"- {item.label}{suffix}")
    lines.append("")
    lines.append("</details>")
    lines.append("")

    lines.append("## Detail by category")
    lines.append("")
    for section in model.detail_sections:
        status_note = "" if section.status == "ok" else f" _(checker status: {section.status})_"
        lines.append("<details>")
        lines.append(f"<summary>{section.label} ({len(section.findings)}){status_note}</summary>")
        lines.append("")
        for f in section.findings:
            source_note = f" `[{f.source}, confidence={f.confidence}]`" if f.source != "heuristic" else ""
            lines.append(f"- **[{f.severity}] {f.title}**{source_note}")
            lines.append(f"  - Fix: {f.fix}")
            lines.append(f"  - Location: `{f.location}`")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines)
