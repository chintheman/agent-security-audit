"""The Checker contract every module under asa/checkers/ implements.

Checkers are plain-function modules, not classes with inheritance --
matching the Hermes engine-module convention (stdlib-only, directly
importable, easy to unit-test in isolation). Each checker module exports:

  CATEGORY: asa.finding.Category           -- the category this module owns
  CHECK_IDS: list[str]                     -- every check_id this module can emit
  activates(manifest) -> bool              -- pure predicate, no side effects
  run(manifest, root, context=None) -> list[Finding]

`context` is an optional dict for cross-cutting, CLI-supplied inputs a
checker may use (e.g. {"baseline_modes": {...}} for permission-drift
detection, {"allow_audit_tools": True} for the supply-chain category's
opt-in npm-audit/pip-audit calls). A checker that doesn't need context
simply ignores it -- `context or {}` is the standard guard.

validate_checker_module() is a defensive sanity check registry.py runs at
import time so a malformed checker fails loudly and immediately, not
mysteriously mid-scan.
"""

from __future__ import annotations

REQUIRED_ATTRS = ("CATEGORY", "CHECK_IDS", "activates", "run")


def validate_checker_module(mod) -> None:
    missing = [attr for attr in REQUIRED_ATTRS if not hasattr(mod, attr)]
    if missing:
        raise TypeError(f"checker module {mod.__name__!r} is missing required attribute(s): {missing}")
    if not callable(mod.activates):
        raise TypeError(f"checker module {mod.__name__!r}.activates must be callable")
    if not callable(mod.run):
        raise TypeError(f"checker module {mod.__name__!r}.run must be callable")
    if not isinstance(mod.CHECK_IDS, (list, tuple)) or not mod.CHECK_IDS:
        raise TypeError(f"checker module {mod.__name__!r}.CHECK_IDS must be a non-empty list")
