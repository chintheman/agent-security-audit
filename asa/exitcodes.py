"""Named exit codes, so `asa scan`'s exit status is documented and stable
for CI/scripting consumers rather than an unlabeled 0/1."""

CLEAN = 0
FINDINGS_PRESENT = 1
ERROR = 2
PARTIAL_UNKNOWN = 3  # scan completed but coverage is incomplete (a checker errored, or a manifest gap was found)
