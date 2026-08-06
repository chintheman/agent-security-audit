"""Explicit checker registry. Not a glob-import-everything -- this list is
the single reviewable point of truth for what runs, matching the
completeness-contract discipline used elsewhere in this tool (nothing
silently included or excluded).

Each entry is a module implementing the Checker contract documented in
asa/checkers/base.py. New checkers get added here, one line, once they
exist -- registry.py imports this list rather than scanning the directory.
"""

from asa.checkers import secrets  # noqa: F401

CHECKER_MODULES = [
    secrets,
]
