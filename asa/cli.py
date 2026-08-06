"""Command-line entry point: `asa scan`, `asa report`, `asa list-checks`.

`asa fix` is added in a later milestone once asa/fixer.py exists.
`--host` (remote-over-SSH) and `--ai` are added once asa/ssh_remote.py and
asa/ai_assist.py exist -- they're deliberately absent from the parser
until then rather than present-but-broken.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from asa import __version__, exitcodes, runner
from asa.checkers.secrets import dotenv_paths
from asa.registry import list_checks
from asa.report.html import render_html
from asa.report.model import build_report_model
from asa.report.text import render_text


def _write_scan_json(out_dir: str, manifest, findings, coverage) -> str:
    os.makedirs(out_dir, exist_ok=True)
    stamp = manifest.scanned_at.replace(":", "-")
    path = os.path.join(out_dir, f"{stamp}-scan.json")
    modes = {}
    for p in dotenv_paths(manifest, manifest.scan_root):
        try:
            modes[p] = os.stat(p).st_mode & 0o777
        except OSError:
            continue
    payload = {
        "manifest": manifest.to_dict(),
        "findings": [f.to_dict() for f in findings],
        "coverage": coverage,
        "dotenv_modes": modes,
        "tool_version": __version__,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def _load_baseline(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return {"baseline_modes": data.get("dotenv_modes", {})}


def _render(model, fmt: str) -> str:
    if fmt == "html":
        return render_html(model)
    if fmt == "json":
        return json.dumps(
            {
                "scanned_target": model.scanned_target,
                "scanned_at": model.scanned_at,
                "tool_version": model.tool_version,
                "pills": [p.__dict__ for p in model.pills],
                "need_you": [n.__dict__ for n in model.need_you],
                "need_you_overflow": model.need_you_overflow,
                "coverage_summary": model.coverage_summary,
                "detail_sections": [
                    {"category": s.category, "label": s.label, "status": s.status,
                     "findings": [f.__dict__ for f in s.findings]}
                    for s in model.detail_sections
                ],
            },
            indent=2,
        )
    return render_text(model, fmt=fmt if fmt in ("term", "md") else "term", verbose=(fmt == "md"))


def _exit_code_for(manifest, coverage, findings) -> int:
    errored = any(info.get("status") == "error" for info in coverage.values())
    gaps = manifest.verify_completeness()
    if errored or gaps:
        return exitcodes.PARTIAL_UNKNOWN
    if findings:
        return exitcodes.FINDINGS_PRESENT
    return exitcodes.CLEAN


def cmd_scan(args) -> int:
    if not os.path.isdir(args.path):
        print(f"error: {args.path!r} is not a directory", file=sys.stderr)
        return exitcodes.ERROR

    context = {}
    if args.baseline:
        try:
            context.update(_load_baseline(args.baseline))
        except (OSError, ValueError) as exc:
            print(f"warning: could not read --baseline {args.baseline!r}: {exc}", file=sys.stderr)

    categories = args.category.split(",") if args.category else None

    manifest, findings, coverage = runner.run(
        args.path,
        scope=args.scope,
        include_vendored=args.include_vendored,
        categories=categories,
        context=context,
    )

    if args.severity_min:
        order = ["critical", "high", "medium", "low", "info"]
        cutoff = order.index(args.severity_min)
        findings = [f for f in findings if order.index(f.severity.value) <= cutoff]

    model = build_report_model(manifest, findings, coverage)
    output = _render(model, args.format)

    # exit code must be decided from what was actually scanned, before this
    # run's own asa-output/ write can appear as a fresh top-level entry and
    # make verify_completeness() (which re-lists the live directory) see a
    # gap the tool just created itself.
    exit_code = _exit_code_for(manifest, coverage, findings)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
    else:
        print(output)

    json_path = _write_scan_json(os.path.join(args.path, "asa-output"), manifest, findings, coverage)
    print(f"(full scan JSON written to {json_path})", file=sys.stderr)

    return exit_code


def cmd_report(args) -> int:
    with open(args.from_json, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    from asa.finding import Category, Evidence, Finding, Severity, Source
    from asa.manifest import Component, Manifest

    m = data["manifest"]
    components = [Component(kind=c["kind"], root=c["root"], signature_files=c["signature_files"], metadata=c["metadata"]) for c in m.get("components", [])]
    manifest = Manifest(
        scan_root=m["scan_root"], scanned_at=m["scanned_at"], components=components,
        skipped=m["skipped"], unreadable=m["unreadable"], host=m["host"],
        walked_top_level=m.get("walked_top_level", []),
        top_level_snapshot=m.get("top_level_snapshot", []),
    )

    findings = []
    for fd in data["findings"]:
        ev = Evidence(**fd["evidence"])
        findings.append(Finding(
            check_id=fd["check_id"], category=Category(fd["category"]), severity=Severity(fd["severity"]),
            title=fd["title"], evidence=ev, fix=fd["fix"], fix_time_estimate=fd.get("fix_time_estimate"),
            location=fd["location"], confidence=fd.get("confidence", "high"), source=Source(fd.get("source", "heuristic")),
            auto_fixable=fd.get("auto_fixable", False), references=fd.get("references", []), id=fd["id"],
        ))

    model = build_report_model(manifest, findings, data["coverage"])
    output = _render(model, args.format)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
    else:
        print(output)
    return _exit_code_for(manifest, data["coverage"], findings)


def cmd_list_checks(args) -> int:
    for c in list_checks(category=args.category):
        print(f"{c['category']:<20} {c['check_id']}")
    return exitcodes.CLEAN


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="asa", description="Standalone, read-only security audit CLI.")
    p.add_argument("--version", action="version", version=f"asa {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a target directory.")
    s.add_argument("path", nargs="?", default=".", help="Directory to scan (default: current directory)")
    s.add_argument("--scope", choices=["project", "machine"], default="project")
    s.add_argument("--format", choices=["term", "md", "html", "json"], default="term")
    s.add_argument("--out", default=None, help="Write rendered report to this file instead of stdout")
    s.add_argument("--severity-min", choices=["critical", "high", "medium", "low", "info"], default=None,
                   help="Only include findings at or above this severity")
    s.add_argument("--category", default=None, help="Comma-separated category filter")
    s.add_argument("--include-vendored", action="store_true")
    s.add_argument("--baseline", default=None, help="Path to a prior scan's JSON output, for drift checks")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("report", help="Re-render a saved scan without re-scanning.")
    r.add_argument("--from-json", required=True)
    r.add_argument("--format", choices=["term", "md", "html", "json"], default="term")
    r.add_argument("--out", default=None)
    r.set_defaults(func=cmd_report)

    lc = sub.add_parser("list-checks", help="List every check any registered checker can emit.")
    lc.add_argument("--category", default=None)
    lc.set_defaults(func=cmd_list_checks)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return exitcodes.ERROR


if __name__ == "__main__":
    sys.exit(main())
