"""Orchestrates a scan: build manifest -> select checkers -> run -> dedupe
-> coverage. A checker module raising an exception never crashes the whole
scan -- it's converted into a single info-level finding noting the
category may be under-reported, and coverage.status records "error" so the
report can surface it rather than silently presenting a clean category
that just failed to run."""

from __future__ import annotations

from asa import manifest as manifest_mod
from asa.finding import Category, Evidence, Finding, Severity, sort_findings
from asa.registry import modules_for


def _error_finding(mod, exc: Exception, stage: str) -> Finding:
    return Finding(
        check_id=f"{mod.CATEGORY.value}.checker_error",
        category=mod.CATEGORY,
        severity=Severity.INFO,
        title=f"Checker '{mod.__name__}' failed during {stage}() -- category may be under-reported",
        evidence=Evidence(detail={"stage": stage, "module": mod.__name__, "error": str(exc)}),
        fix="This is a bug in the tool itself, not your target. Please file an issue including this message.",
        location=mod.__name__,
    )


def run(
    scan_root: str,
    *,
    scope: str = "project",
    include_vendored: bool = False,
    home_dir: str | None = None,
    is_remote: bool = False,
    categories: list | None = None,
    context: dict | None = None,
):
    """Returns (manifest, findings, coverage).

    coverage: {category_value: {"activated": bool|None, "status": "ok"|"not_activated"|"error", "error": str|None}}
    """
    m = manifest_mod.build(scan_root, scope=scope, include_vendored=include_vendored, home_dir=home_dir, is_remote=is_remote)
    root = m.scan_root

    findings: list = []
    coverage: dict = {}
    seen_ids: set = set()

    for mod in modules_for():
        cat = mod.CATEGORY.value
        if categories and cat not in categories:
            continue

        try:
            active = mod.activates(m)
        except Exception as exc:  # noqa: BLE001 -- a bad checker must not kill the scan
            coverage[cat] = {"activated": None, "status": "error", "error": f"activates() raised: {exc}"}
            findings.append(_error_finding(mod, exc, "activates"))
            continue

        if not active:
            coverage[cat] = {"activated": False, "status": "not_activated", "error": None}
            continue

        try:
            mod_findings = mod.run(m, root, context)
        except Exception as exc:  # noqa: BLE001
            coverage[cat] = {"activated": True, "status": "error", "error": f"run() raised: {exc}"}
            findings.append(_error_finding(mod, exc, "run"))
            continue

        coverage[cat] = {"activated": True, "status": "ok", "error": None}
        for f in mod_findings:
            if f.id in seen_ids:
                continue
            seen_ids.add(f.id)
            findings.append(f)

    return m, sort_findings(findings), coverage
