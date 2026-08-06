"""Finding-list -> ReportModel transform. This is the ADHD-friendly report
shape: a pill bar of counts, a short "Need You" list (severity-first, each
with a concrete next step and time estimate), a collapsed clean/fixed
section, and per-category detail blocks behind a fold.

Deliberate deviation from the original plan text: the plan called for a
separate FIX_NEXT_STEP_TEMPLATES table keyed by check_id. Every checker
already populates Finding.fix and Finding.fix_time_estimate per-instance
(e.g. "chmod 600 /exact/path" rather than a generic template) -- richer
than a static table and with no duplication risk between two sources of
truth. Kept the plan's actual intent (a check without fix guidance must
fail a test, not ship silently) via test_model.py asserting every Finding
from every registered checker has both fields populated, rather than via a
parallel template table.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from asa import __version__
from asa.finding import Severity

MAX_NEED_YOU_ITEMS = 7

# check_ids whose recommended fix is specifically "rotate this credential"
# -- distinct from a permission/rename fix, used for the "To Rotate" pill.
ROTATE_CHECK_IDS = {
    "secrets.hardcoded_value_instead_of_env_ref",
    "secrets.credential_shaped_string_anywhere",
    "secrets.duplicate_secret_value_different_names",
    "secrets.secret_in_git_history",
}

SEVERITY_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}


@dataclass
class Pill:
    label: str
    count: int
    tone: str  # "critical" | "high" | "good" | "neutral"


@dataclass
class NeedYouItem:
    finding_id: str
    title: str
    next_step: str
    time_estimate: str
    severity: str
    location: str


@dataclass
class CleanItem:
    kind: str  # "clean_category" | "low_severity_finding"
    label: str
    detail: str = ""


@dataclass
class DetailFinding:
    id: str
    title: str
    severity: str
    fix: str
    location: str
    evidence: dict
    confidence: str
    source: str
    auto_fixable: bool


@dataclass
class DetailSection:
    category: str
    label: str
    findings: list = field(default_factory=list)
    status: str = "ok"  # mirrors coverage status for this category


@dataclass
class ReportModel:
    scanned_target: str
    scanned_at: str
    tool_version: str
    pills: list
    need_you: list
    need_you_overflow: int
    fixed_or_clean: list
    detail_sections: list
    coverage_summary: str
    fixed_count: int = 0
    ai_assist_summary: str | None = None


def _coverage_summary(manifest, coverage: dict) -> str:
    gaps = manifest.verify_completeness()
    parts = [
        f"{len(manifest.components)} component(s) detected",
        f"{len(manifest.skipped)} skipped",
    ]
    if manifest.unreadable:
        parts.append(f"{len(manifest.unreadable)} unreadable")
    parts.append(f"{len(gaps)} unaccounted" if gaps else "0 unaccounted")

    errored = [cat for cat, info in coverage.items() if info.get("status") == "error"]
    summary = ", ".join(parts)
    if errored:
        summary += f" -- checker error in: {', '.join(sorted(errored))} (that category may be under-reported)"
    return summary


def build_report_model(manifest, findings: list, coverage: dict, *, fixed_count: int = 0, ai_assist_summary: str | None = None, scanned_target: str | None = None) -> ReportModel:
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    high = [f for f in findings if f.severity == Severity.HIGH]
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    low = [f for f in findings if f.severity == Severity.LOW]
    info = [f for f in findings if f.severity == Severity.INFO]

    need_you_candidates = [f for f in (critical + high) if not f.auto_fixable]
    need_you_all = need_you_candidates  # already severity-sorted (findings list is pre-sorted by runner)
    need_you = need_you_all[:MAX_NEED_YOU_ITEMS]
    overflow = max(0, len(need_you_all) - MAX_NEED_YOU_ITEMS)

    need_you_items = [
        NeedYouItem(
            finding_id=f.id,
            title=f.title,
            next_step=f.fix,
            time_estimate=f.fix_time_estimate or "unknown",
            severity=SEVERITY_LABEL[f.severity],
            location=f.location,
        )
        for f in need_you
    ]

    to_rotate = [f for f in findings if f.check_id in ROTATE_CHECK_IDS]
    clean_categories = [cat for cat, info_c in coverage.items() if info_c.get("status") == "ok" and not any(f.category.value == cat for f in findings)]

    fixed_or_clean = []
    for cat in sorted(clean_categories):
        fixed_or_clean.append(CleanItem(kind="clean_category", label=f"{cat}: no findings"))
    for f in low + medium:
        if f not in need_you and f.check_id not in ("checker_error",):
            fixed_or_clean.append(CleanItem(kind="low_severity_finding", label=f.title, detail=f.location))

    auto_fixable_not_needed = [f for f in (critical + high) if f.auto_fixable]
    for f in auto_fixable_not_needed:
        fixed_or_clean.append(CleanItem(kind="auto_fixable_pending", label=f.title, detail=f"run `asa fix` -- {f.location}"))

    pills = [
        Pill(label="Fixed", count=fixed_count, tone="good"),
        Pill(label="Needs You", count=len(need_you_all), tone="critical" if need_you_all else "good"),
        Pill(label="To Rotate", count=len(to_rotate), tone="critical" if to_rotate else "good"),
        Pill(label="Clean", count=len(clean_categories), tone="neutral"),
    ]

    by_category: dict = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)

    detail_sections = []
    for cat in sorted(coverage.keys()):
        cat_findings = by_category.get(_category_enum_for(cat), [])
        detail_sections.append(DetailSection(
            category=cat,
            label=cat.replace("-", " ").title(),
            status=coverage[cat].get("status", "unknown"),
            findings=[
                DetailFinding(
                    id=f.id, title=f.title, severity=SEVERITY_LABEL[f.severity],
                    fix=f.fix, location=f.location, evidence=f.evidence.to_dict(),
                    confidence=f.confidence, source=f.source.value, auto_fixable=f.auto_fixable,
                )
                for f in cat_findings
            ],
        ))

    return ReportModel(
        scanned_target=scanned_target or manifest.scan_root,
        scanned_at=manifest.scanned_at,
        tool_version=__version__,
        pills=pills,
        need_you=need_you_items,
        need_you_overflow=overflow,
        fixed_or_clean=fixed_or_clean,
        detail_sections=detail_sections,
        coverage_summary=_coverage_summary(manifest, coverage),
        fixed_count=fixed_count,
        ai_assist_summary=ai_assist_summary,
    )


def _category_enum_for(value: str):
    from asa.finding import Category
    for c in Category:
        if c.value == value:
            return c
    return None
