"""Shared (dict -> Manifest/Finding/coverage) reconstruction. Used by both
`asa report`/`asa fix` (reading a saved asa-output/*.json file) and
ssh_remote.py (reading an in-memory dict parsed from a remote process's
stdout) -- one deserialization path instead of two copies drifting apart.
"""

from __future__ import annotations

from asa.finding import Category, Evidence, Finding, Severity, Source
from asa.manifest import Component, Manifest


def scan_data_to_objects(data: dict):
    """Returns (manifest, findings, coverage) from a scan payload shaped
    like _write_scan_json()'s output -- {"manifest": ..., "findings": [...],
    "coverage": ...}."""
    m = data["manifest"]
    components = [
        Component(kind=c["kind"], root=c["root"], signature_files=c["signature_files"], metadata=c["metadata"])
        for c in m.get("components", [])
    ]
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

    return manifest, findings, data["coverage"]
