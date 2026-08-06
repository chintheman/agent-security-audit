"""Checker discovery/activation matching. Reads the explicit CHECKER_MODULES
list from asa/checkers/__init__.py -- deliberately not a directory glob, so
"what runs" has one reviewable point of truth."""

from __future__ import annotations

from asa.checkers import CHECKER_MODULES
from asa.checkers.base import validate_checker_module

for _mod in CHECKER_MODULES:
    validate_checker_module(_mod)


def list_checks(category: str | None = None) -> list:
    """Returns [{"category", "check_id", "module"}] for every check any
    registered checker module can emit -- feeds `asa list-checks`."""
    out = []
    for mod in CHECKER_MODULES:
        if category and mod.CATEGORY.value != category:
            continue
        for check_id in mod.CHECK_IDS:
            out.append({"category": mod.CATEGORY.value, "check_id": check_id, "module": mod.__name__})
    return out


def modules_for(category: str | None = None) -> list:
    if category is None:
        return list(CHECKER_MODULES)
    return [m for m in CHECKER_MODULES if m.CATEGORY.value == category]
