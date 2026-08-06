"""Inventory + signature-detection engine. Walks a target directory (and
optionally the user's home directory for machine-level components),
classifies what it finds using asa/data/signatures.py, and produces a
Manifest that every checker's activation predicate reads.

Completeness contract, borrowed from the claude-security plugin's
inventory-agent discipline: every top-level path directly under scan_root
must land in a Component's root, in `skipped`, or in `unreadable` --
verify_completeness() proves this rather than trusting the walk silently.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

from asa.data.signatures import SIGNATURES, VENDORED_DIR_NAMES, detect_machine_signatures


@dataclass
class Component:
    kind: str
    root: str
    signature_files: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "root": self.root, "signature_files": self.signature_files, "metadata": self.metadata}


@dataclass
class Manifest:
    scan_root: str
    scanned_at: str
    components: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    unreadable: list = field(default_factory=list)
    host: dict = field(default_factory=dict)

    def has_kind(self, kind: str) -> bool:
        return any(c.kind == kind for c in self.components)

    def components_of(self, kind: str) -> list:
        return [c for c in self.components if c.kind == kind]

    def verify_completeness(self) -> list:
        """Returns unaccounted top-level entries directly under scan_root.
        Empty list means every immediate child of scan_root is explained by
        a component, a skip reason, or an unreadable-path reason."""
        try:
            top_level = set(os.listdir(self.scan_root))
        except OSError:
            # scan_root itself unreadable -- that's its own unreadable entry,
            # already recorded by build(); nothing further to reconcile.
            return []

        accounted = set()
        for c in self.components:
            first_segment = c.root.split(os.sep, 1)[0]
            accounted.add(first_segment)
        for entry in self.skipped:
            rel = os.path.relpath(entry["path"], self.scan_root)
            first_segment = rel.split(os.sep, 1)[0]
            accounted.add(first_segment)
        for entry in self.unreadable:
            rel = os.path.relpath(entry["path"], self.scan_root)
            first_segment = rel.split(os.sep, 1)[0]
            accounted.add(first_segment)
        # scan_root itself matching a component (root == ".") accounts for
        # everything directly.
        if any(c.root in (".", "") for c in self.components):
            return []

        return sorted(top_level - accounted)

    def to_dict(self) -> dict:
        return {
            "scan_root": self.scan_root,
            "scanned_at": self.scanned_at,
            "components": [c.to_dict() for c in self.components],
            "skipped": self.skipped,
            "unreadable": self.unreadable,
            "host": self.host,
        }


def _host_info(is_remote: bool = False) -> dict:
    return {
        "os": platform.system(),
        "hostname": platform.node(),
        "is_remote": is_remote,
        "python_version": platform.python_version(),
    }


def iter_files(scan_root: str, *, include_vendored: bool = False):
    """Yield absolute file paths under scan_root, pruning vendored dirs the
    same way build() does. Shared walk helper so checkers don't each
    re-implement vendored-dir pruning independently."""
    scan_root = os.path.abspath(os.path.expanduser(scan_root))
    for dirpath, dirnames, filenames in os.walk(scan_root, topdown=True, onerror=lambda e: None):
        if not include_vendored:
            for d in list(dirnames):
                if d in VENDORED_DIR_NAMES or d.endswith(".egg-info"):
                    dirnames.remove(d)
        for f in filenames:
            yield os.path.join(dirpath, f)


def build(scan_root: str, *, scope: str = "project", include_vendored: bool = False, home_dir: str | None = None, is_remote: bool = False) -> Manifest:
    """Build a Manifest for scan_root. scope="machine" additionally checks
    fixed machine-level paths under home_dir (defaults to the invoking
    user's home directory)."""
    scan_root = os.path.abspath(os.path.expanduser(scan_root))
    components: list = []
    skipped: list = []
    unreadable: list = []

    def onerror(exc: OSError) -> None:
        unreadable.append({"path": exc.filename or scan_root, "reason": str(exc)})

    for dirpath, dirnames, filenames in os.walk(scan_root, topdown=True, onerror=onerror):
        # prune vendored dirs, recording why
        for d in list(dirnames):
            if d in VENDORED_DIR_NAMES and not include_vendored:
                skipped.append({"path": os.path.join(dirpath, d), "reason": "vendored/build artifact, excluded by default"})
                dirnames.remove(d)
            elif not include_vendored and (d.endswith(".egg-info")):
                skipped.append({"path": os.path.join(dirpath, d), "reason": "vendored/build artifact, excluded by default"})
                dirnames.remove(d)

        rel_root = os.path.relpath(dirpath, scan_root)

        for sig in SIGNATURES:
            try:
                hit_files = sig.matcher(dirpath, filenames, dirnames)
            except Exception as exc:  # a bad matcher must not kill the whole walk
                unreadable.append({"path": dirpath, "reason": f"signature matcher '{sig.kind}' raised: {exc}"})
                continue
            if hit_files:
                components.append(Component(kind=sig.kind, root=rel_root, signature_files=hit_files, metadata={}))

    if scope == "machine":
        home = os.path.abspath(os.path.expanduser(home_dir or "~"))
        for kind, root_path, marker in detect_machine_signatures(home):
            components.append(Component(kind=kind, root=root_path, signature_files=[marker], metadata={"machine_level": True}))

    manifest = Manifest(
        scan_root=scan_root,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        components=components,
        skipped=skipped,
        unreadable=unreadable,
        host=_host_info(is_remote=is_remote),
    )
    return manifest
