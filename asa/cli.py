"""Command-line entry point: `asa scan`, `asa report`, `asa fix`,
`asa list-checks`.

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


def _render(model, fmt: str, verbose: bool = False) -> str:
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
    return render_text(model, fmt=fmt if fmt in ("term", "md") else "term", verbose=verbose or (fmt == "md"))


def _exit_code_for(manifest, coverage, findings) -> int:
    errored = any(info.get("status") == "error" for info in coverage.values())
    gaps = manifest.verify_completeness()
    if errored or gaps:
        return exitcodes.PARTIAL_UNKNOWN
    if findings:
        return exitcodes.FINDINGS_PRESENT
    return exitcodes.CLEAN


def cmd_scan(args) -> int:
    context = {}
    if args.baseline:
        try:
            context.update(_load_baseline(args.baseline))
        except (OSError, ValueError) as exc:
            print(f"warning: could not read --baseline {args.baseline!r}: {exc}", file=sys.stderr)

    categories = args.category.split(",") if args.category else None

    if args.host:
        from asa import ssh_remote
        try:
            manifest, findings, coverage = ssh_remote.run(
                args.host, scan_root=args.path, scope=args.scope,
                include_vendored=args.include_vendored, categories=categories, context=context,
            )
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return exitcodes.ERROR
        # nothing local to write asa-output into on the remote's behalf --
        # lands in the current directory instead of a path that doesn't
        # exist on this machine.
        out_dir = os.path.join(".", "asa-output")
    else:
        if not os.path.isdir(args.path):
            print(f"error: {args.path!r} is not a directory", file=sys.stderr)
            return exitcodes.ERROR
        manifest, findings, coverage = runner.run(
            args.path,
            scope=args.scope,
            include_vendored=args.include_vendored,
            categories=categories,
            context=context,
        )
        out_dir = os.path.join(args.path, "asa-output")

    if args.severity_min:
        order = ["critical", "high", "medium", "low", "info"]
        cutoff = order.index(args.severity_min)
        findings = [f for f in findings if order.index(f.severity.value) <= cutoff]

    model = build_report_model(manifest, findings, coverage)
    output = _render(model, args.format, verbose=args.verbose)

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

    json_path = _write_scan_json(out_dir, manifest, findings, coverage)
    print(f"(full scan JSON written to {json_path})", file=sys.stderr)

    return exit_code


def _load_scan_json(path: str):
    """Reconstructs (manifest, findings, coverage) from a saved
    asa-output/*.json -- shared by `report` and `fix`, both of which
    operate on a prior scan's output rather than the live filesystem."""
    from asa.serialize import scan_data_to_objects

    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return scan_data_to_objects(data)


def cmd_report(args) -> int:
    manifest, findings, coverage = _load_scan_json(args.from_json)
    model = build_report_model(manifest, findings, coverage)
    output = _render(model, args.format, verbose=args.verbose)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
    else:
        print(output)
    return _exit_code_for(manifest, coverage, findings)


def cmd_fix(args) -> int:
    from asa import fixer

    manifest, findings, coverage = _load_scan_json(args.from_json)
    if manifest.host.get("is_remote"):
        print("error: this scan was run over SSH (--host). asa fix only operates on the local filesystem in v1 -- no mutating a remote box from here.", file=sys.stderr)
        return exitcodes.ERROR
    if args.only_check_id:
        wanted = set(args.only_check_id.split(","))
        findings = [f for f in findings if f.check_id in wanted]

    fixable = [f for f in findings if fixer.is_auto_fixable(f.check_id)]
    if not fixable:
        print("Nothing in this scan is auto-fixable (chmod-only, 3 check types). Nothing to do.")
        return exitcodes.CLEAN

    mode = "dry-run" if args.dry_run else ("yes" if args.yes else "ask-each")
    log_dir = os.path.join(os.path.dirname(os.path.dirname(args.from_json)) or ".", "asa-output")
    results = fixer.apply(fixable, mode=mode, log_dir=log_dir)

    applied = sum(1 for r in results if r.applied)
    skipped = [r for r in results if not r.applied]
    print(f"\n{applied}/{len(results)} fixes applied.")
    for r in skipped:
        print(f"  skipped: {r.path} ({r.skipped_reason})")

    return exitcodes.CLEAN if applied or not skipped else exitcodes.FINDINGS_PRESENT


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
    s.add_argument("--host", default=None, help="Scan a remote box over SSH instead of the local filesystem (e.g. user@myhost). Uses your existing SSH access -- this tool never manages credentials itself.")
    s.add_argument("--verbose", action="store_true", help="Show full per-category detail in term output (md/html always show it)")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("report", help="Re-render a saved scan without re-scanning.")
    r.add_argument("--from-json", required=True)
    r.add_argument("--format", choices=["term", "md", "html", "json"], default="term")
    r.add_argument("--out", default=None)
    r.add_argument("--verbose", action="store_true", help="Show full per-category detail in term output (md/html always show it)")
    r.set_defaults(func=cmd_report)

    fx = sub.add_parser("fix", help="Apply the narrow set of safe, reversible fixes (chmod-only) from a prior scan.")
    fx.add_argument("--from-json", required=True)
    fx.add_argument("--dry-run", action="store_true", help="Print what would run, apply nothing")
    fx.add_argument("--yes", action="store_true", help="Apply every fixable finding without prompting")
    fx.add_argument("--only-check-id", default=None, help="Comma-separated check_id filter")
    fx.set_defaults(func=cmd_fix)

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
