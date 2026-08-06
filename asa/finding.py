"""Finding schema: the single data shape every checker emits and every
report renderer consumes. Nothing outside this module should construct a
Finding by hand-building a dict -- always go through this dataclass so the
shape stays consistent.

Evidence NEVER carries a raw secret value. See asa/redact.py for the
masking/hashing helpers that produce Evidence.snippet and value_hash8.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Fixed ordering, most severe first -- used for sorting findings before
# they're handed to the report layer.
SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class Category(str, Enum):
    SECRETS = "secrets"
    PERMISSIONS = "permissions"
    NETWORK = "network"
    AGENT = "agent-blast-radius"
    SUPPLY_CHAIN = "supply-chain"
    CI = "git-ci-injection"


class Source(str, Enum):
    HEURISTIC = "heuristic"
    AI_ASSIST = "ai-assist"


@dataclass
class Evidence:
    """Never contains a raw secret value -- only shape/location metadata.

    value_hash8: first 8 hex chars of sha256(value). Correlation/dedup
    only -- NOT reversible to the value, and deliberately truncated so it
    can't be used as a rainbow-table lookup key for short secrets either.
    """

    file: str | None = None
    line: int | None = None
    variable_name: str | None = None
    value_length: int | None = None
    value_hash8: str | None = None
    snippet: str | None = None
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "variable_name": self.variable_name,
            "value_length": self.value_length,
            "value_hash8": self.value_hash8,
            "snippet": self.snippet,
            "detail": self.detail,
        }


@dataclass
class Finding:
    check_id: str
    category: Category
    severity: Severity
    title: str
    evidence: Evidence
    fix: str
    location: str
    fix_time_estimate: str | None = None
    confidence: str = "high"
    source: Source = Source.HEURISTIC
    auto_fixable: bool = False
    references: list = field(default_factory=list)
    id: str = field(default="")

    def __post_init__(self) -> None:
        if not self.id:
            self.id = compute_finding_id(self.category, self.check_id, self.location)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "check_id": self.check_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "evidence": self.evidence.to_dict(),
            "fix": self.fix,
            "fix_time_estimate": self.fix_time_estimate,
            "location": self.location,
            "confidence": self.confidence,
            "source": self.source.value,
            "auto_fixable": self.auto_fixable,
            "references": self.references,
        }


def compute_finding_id(category: Category, check_id: str, location: str) -> str:
    """Deterministic, not random -- so re-running the tool on an unchanged
    target produces the same Finding.id, which is what makes --baseline
    drift comparisons and `asa report --from-json` diffing possible."""
    cat = category.value if isinstance(category, Category) else str(category)
    digest = hashlib.sha256(location.encode("utf-8", "surrogateescape")).hexdigest()[:8]
    return f"{cat}.{check_id}.{digest}"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Severity-first, then category, then id -- stable and deterministic
    so report output doesn't reshuffle between runs with identical input."""
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(
        findings,
        key=lambda f: (order.get(f.severity, len(order)), f.category.value, f.id),
    )
