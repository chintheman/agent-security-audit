"""Secrets/credential-hygiene checks. The richest category, built first
because it's the one with the most real audit findings behind it.

Seven checks:
  1. hardcoded_value_instead_of_env_ref  -- config file, credential-shaped
     key, literal value instead of an env-var reference
  2. credential_shaped_string_anywhere   -- shape scan across all text
  3. dotenv_world_readable               -- .env* file mode allows group/other read
  4. dotenv_permission_drift             -- mode looser than a supplied baseline
  5. generic_env_var_name_collision      -- PASSWORD/EMAIL/KEY etc. reused
     across unrelated components
  6. duplicate_secret_value_different_names -- same value, two different names
  7. secret_in_git_history               -- credential shape in `git log -p`
"""

from __future__ import annotations

import os
import re
import subprocess

from asa import redact
from asa.finding import Category, Evidence, Finding, Severity
from asa.manifest import iter_files

CATEGORY = Category.SECRETS
CHECK_IDS = [
    "secrets.hardcoded_value_instead_of_env_ref",
    "secrets.credential_shaped_string_anywhere",
    "secrets.dotenv_world_readable",
    "secrets.dotenv_permission_drift",
    "secrets.generic_env_var_name_collision",
    "secrets.duplicate_secret_value_different_names",
    "secrets.secret_in_git_history",
]

CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".cfg", ".service"}

# extensions/content we never want to open as text -- binary formats where
# "scan every line" is meaningless and can be genuinely slow/wrong.
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".pdf",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".mov", ".avi", ".wav",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".pyc",
    ".db", ".sqlite", ".sqlite3",
}
MAX_SCAN_BYTES = 1_000_000  # skip files larger than this for the full-text shape scan

PLACEHOLDER_VALUES = {
    "", "changeme", "change_me", "xxx", "xxxx", "todo", "fixme",
    "your-key-here", "your_key_here", "example", "test", "fake",
    "null", "none", "true", "false", "n/a", "na", "placeholder",
    "<redacted>", "***", "secret", "password", "insert-key-here",
}

GENERIC_ENV_NAMES = {"PASSWORD", "EMAIL", "KEY", "TOKEN", "SECRET", "API_KEY", "USERNAME"}

DOTENV_FILENAME = re.compile(r"^\.env(\..+)?$")


def activates(manifest) -> bool:
    return True  # secrets hygiene is worth checking on any target, project or machine scope


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"").lower()
    if not v:
        return True
    if v in PLACEHOLDER_VALUES:
        return True
    if len(set(v)) == 1 and len(v) > 1:  # single repeated character, e.g. "xxxxxx"
        return True
    return False


def _parse_dotenv(path: str) -> list:
    """Returns (line_no, key, value, raw_line) for KEY=VALUE lines."""
    pairs = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                s = stripped[7:] if stripped.startswith("export ") else stripped
                if "=" not in s:
                    continue
                key, _, value = s.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                    pairs.append((i, key, value, line.rstrip("\n")))
    except OSError:
        pass
    return pairs


def _check_hardcoded_value_instead_of_env_ref(manifest, root) -> list:
    from asa.data.secret_patterns import CREDENTIAL_KEY_NAME_PATTERN, ENV_REF_PATTERN

    findings = []
    key_value_line = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_.\-]*)\s*[:=]\s*(.+?)\s*,?\s*$")

    for filepath in iter_files(root):
        ext = os.path.splitext(filepath)[1]
        basename = os.path.basename(filepath)
        if ext not in CONFIG_EXTENSIONS or DOTENV_FILENAME.match(basename):
            continue
        try:
            if os.path.getsize(filepath) > MAX_SCAN_BYTES:
                continue
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue

        for i, line in enumerate(lines, start=1):
            m = key_value_line.match(line)
            if not m:
                continue
            key, raw_value = m.group(1), m.group(2)
            if not CREDENTIAL_KEY_NAME_PATTERN.search(key):
                continue
            value = raw_value.strip().strip('"').strip("'")
            if not value or _is_placeholder(value):
                continue
            if ENV_REF_PATTERN.search(raw_value):
                continue  # already an env-var reference, not hardcoded
            evidence = Evidence(**redact.evidence_dict(
                value=value, file=os.path.relpath(filepath, root), line=i,
                variable_name=key, raw_line=line,
            ))
            findings.append(Finding(
                check_id="secrets.hardcoded_value_instead_of_env_ref",
                category=CATEGORY,
                severity=Severity.HIGH,
                title=f"Hardcoded value for '{key}' instead of an environment-variable reference",
                evidence=evidence,
                fix=f"Replace the literal value with an env-var reference (e.g. ${{{key}}}) and set {key} outside version control.",
                fix_time_estimate="5 min",
                location=f"{os.path.relpath(filepath, root)}:{i}",
            ))
    return findings


def _check_credential_shaped_string_anywhere(manifest, root) -> list:
    findings = []
    for filepath in iter_files(root):
        ext = os.path.splitext(filepath)[1]
        basename = os.path.basename(filepath)
        if ext in BINARY_EXTENSIONS or DOTENV_FILENAME.match(basename):
            continue
        try:
            if os.path.getsize(filepath) > MAX_SCAN_BYTES:
                continue
            with open(filepath, "r", encoding="utf-8", errors="strict") as fh:
                lines = fh.readlines()
        except (OSError, UnicodeDecodeError):
            continue

        for i, line in enumerate(lines, start=1):
            hits = redact.find_credential_shapes(line)
            for name, start, end, matched in hits:
                severity = Severity.MEDIUM if name == "generic_high_entropy_hex_or_b64" else Severity.HIGH
                evidence = Evidence(**redact.evidence_dict(
                    value=matched, file=os.path.relpath(filepath, root), line=i,
                    variable_name=None, raw_line=line, detail={"pattern": name},
                ))
                findings.append(Finding(
                    check_id="secrets.credential_shaped_string_anywhere",
                    category=CATEGORY,
                    severity=severity,
                    title=f"Credential-shaped string ({name}) found in source",
                    evidence=evidence,
                    fix="Confirm whether this is a real credential; if so, rotate it and move it to an env var or secret store.",
                    fix_time_estimate="10 min",
                    location=f"{os.path.relpath(filepath, root)}:{i}",
                    confidence="medium" if severity == Severity.MEDIUM else "high",
                ))
    return findings


def dotenv_paths(manifest, root) -> list:
    """Absolute, normalized paths -- normpath matters here because
    Component.root can be "." (relpath of scan_root itself), and an
    un-normalized os.path.join produces "root/./.env" which is a different
    STRING from "root/.env" even though it's the same file. Callers
    (including baseline dicts keyed by path) depend on this being
    canonical."""
    paths = []
    for comp in manifest.components_of("dotenv_files"):
        comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        for f in comp.signature_files:
            paths.append(os.path.normpath(os.path.join(comp_dir, f)))
    return paths


def _check_dotenv_world_readable(manifest, root) -> list:
    findings = []
    for path in dotenv_paths(manifest, root):
        try:
            mode = os.stat(path).st_mode
        except OSError:
            continue
        if mode & 0o077:
            findings.append(Finding(
                check_id="secrets.dotenv_world_readable",
                category=CATEGORY,
                severity=Severity.HIGH,
                title=f"{os.path.basename(path)} is readable by users other than its owner",
                evidence=Evidence(file=os.path.relpath(path, root) if path.startswith(root) else path,
                                   detail={"mode": oct(mode & 0o777), "expected": "0600"}),
                fix=f"chmod 600 {path}",
                fix_time_estimate="1 min",
                location=path,
                auto_fixable=True,
            ))
    return findings


def _check_dotenv_permission_drift(manifest, root, context) -> list:
    baseline = (context or {}).get("baseline_modes")
    if not baseline:
        return []  # coverage layer (runner.py) records "no baseline supplied"
    findings = []
    for path in dotenv_paths(manifest, root):
        try:
            current_mode = os.stat(path).st_mode & 0o777
        except OSError:
            continue
        old_mode = baseline.get(path)
        if old_mode is not None and (current_mode & 0o077) > (old_mode & 0o077):
            findings.append(Finding(
                check_id="secrets.dotenv_permission_drift",
                category=CATEGORY,
                severity=Severity.CRITICAL,
                title=f"{os.path.basename(path)} permissions loosened since the last scan",
                evidence=Evidence(file=path, detail={"was": oct(old_mode), "now": oct(current_mode)}),
                fix=f"chmod 600 {path} -- and find out what's resetting it (a dashboard edit, a service restart, etc.)",
                fix_time_estimate="1 min",
                location=path,
                auto_fixable=True,
            ))
    return findings


def _check_generic_env_var_name_collision(manifest, root) -> list:
    locations_by_name: dict = {}
    for path in dotenv_paths(manifest, root):
        for _, key, value, _raw in _parse_dotenv(path):
            if key.upper() in GENERIC_ENV_NAMES and not _is_placeholder(value):
                locations_by_name.setdefault(key.upper(), set()).add(os.path.relpath(path, root) if path.startswith(root) else path)

    findings = []
    for name, locs in locations_by_name.items():
        if len(locs) > 1:
            findings.append(Finding(
                check_id="secrets.generic_env_var_name_collision",
                category=CATEGORY,
                severity=Severity.MEDIUM,
                title=f"Generic variable name '{name}' reused across {len(locs)} separate files",
                evidence=Evidence(variable_name=name, detail={"locations": sorted(locs)}),
                fix=f"Rename {name} to something tool-specific in each file (e.g. SUBSTACK_{name}) so unrelated tools don't inherit each other's credential.",
                fix_time_estimate="5 min per file",
                location=", ".join(sorted(locs)),
            ))
    return findings


def _check_duplicate_secret_value_different_names(manifest, root) -> list:
    by_hash: dict = {}
    for path in dotenv_paths(manifest, root):
        rel = os.path.relpath(path, root) if path.startswith(root) else path
        for _, key, value, _raw in _parse_dotenv(path):
            if _is_placeholder(value) or len(value) < 6:
                continue
            h = redact.hash8(value)
            by_hash.setdefault(h, []).append((rel, key))

    findings = []
    for h, entries in by_hash.items():
        distinct_names = {(loc, key) for loc, key in entries}
        names_only = {key for _, key in entries}
        if len(distinct_names) > 1 and len(names_only) > 1:
            locs_desc = ", ".join(f"{loc}:{key}" for loc, key in sorted(distinct_names))
            findings.append(Finding(
                check_id="secrets.duplicate_secret_value_different_names",
                category=CATEGORY,
                severity=Severity.MEDIUM,
                title=f"Same secret value stored under {len(names_only)} different variable names",
                evidence=Evidence(value_hash8=h, detail={"locations": locs_desc}),
                fix="Confirm this duplication is intentional; if not, pick one name and update all consumers to reference it.",
                fix_time_estimate="10 min",
                location=locs_desc,
            ))
    return findings


CREDENTIAL_FILE_GLOBS = ["*.env*", "*.pem", "*.key", "*secret*", "*credential*", "*password*"]


def _check_secret_in_git_history(manifest, root) -> list:
    if not os.path.isdir(os.path.join(root, ".git")):
        return []
    try:
        proc = subprocess.run(
            ["git", "log", "-p", "--all", "--", *CREDENTIAL_FILE_GLOBS],
            cwd=root, capture_output=True, text=True, timeout=30, errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []

    findings = []
    seen_hashes = set()
    for line in proc.stdout.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        hits = redact.find_credential_shapes(line)
        for name, start, end, matched in hits:
            h = redact.hash8(matched)
            if h in seen_hashes:
                continue
            seen_hashes.add(h)
            findings.append(Finding(
                check_id="secrets.secret_in_git_history",
                category=CATEGORY,
                severity=Severity.CRITICAL,
                title=f"Credential-shaped string ({name}) found in git history",
                evidence=Evidence(value_hash8=h, value_length=len(matched), detail={"pattern": name}),
                fix="Treat as compromised, rotate it. Do not attempt to rewrite git history with this tool.",
                fix_time_estimate="varies by provider",
                location=f"{root} (git history)",
            ))
    return findings


def run(manifest, root, context=None) -> list:
    findings = []
    findings += _check_hardcoded_value_instead_of_env_ref(manifest, root)
    findings += _check_credential_shaped_string_anywhere(manifest, root)
    findings += _check_dotenv_world_readable(manifest, root)
    findings += _check_dotenv_permission_drift(manifest, root, context)
    findings += _check_generic_env_var_name_collision(manifest, root)
    findings += _check_duplicate_secret_value_different_names(manifest, root)
    findings += _check_secret_in_git_history(manifest, root)
    return findings
