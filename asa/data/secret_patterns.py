"""Credential-shape regex patterns, used by asa/redact.py and by the
secrets checker. Kept as a declarative data table (not scattered inline
regexes) so adding a new provider's key shape is a one-line addition here,
not a hunt through the codebase.

All patterns are compiled with Python's own `re` module. Nothing in this
file, or anything that consumes it, may shell out to `sed`/`grep` for
matching -- see the regression test in tests/test_redact.py named after the
real incident this rule exists to prevent (a masking regex silently
no-op'ing under BSD sed on macOS).
"""

from __future__ import annotations

import re

# (name, compiled pattern). Patterns match the CREDENTIAL VALUE shape
# itself (not the variable name it might be assigned to -- that's a
# separate, complementary signal used by the "keyword scan" side of the
# secrets checker).
CREDENTIAL_SHAPE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("github_pat_classic", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_oauth_token", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("github_pat_fine_grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("github_app_token", re.compile(r"\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b")),
    ("google_api_key", re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----")),
    (
        # Deliberately excludes "/" from the character class. It's part of
        # the base64 alphabet, but including it here made this pattern
        # match straight through entire filesystem paths as one long run
        # ("/var/folders/.../tmpXXXXXX" reads as 40+ contiguous
        # "high-entropy" characters once "/" is a valid member) -- a real
        # false positive caught by ai_assist.py's tests, and the same
        # pattern this checker uses, so it would have hit ordinary source
        # code containing file paths too. Without "/", a real path's
        # slash-separated segments break the match at each boundary, and
        # ordinary path segments are almost always under the 32-char floor.
        "generic_high_entropy_hex_or_b64",
        re.compile(r"\b(?=[A-Za-z0-9+_=-]{32,}\b)(?=[^A-Za-z]*[A-Za-z])(?=[^0-9]*[0-9])[A-Za-z0-9+_=-]{32,}\b"),
    ),
]

# Credential-shaped variable/key NAMES -- used by the "hardcoded value
# instead of env-ref" keyword scan (complementary to the shape scan above:
# a value can be credential-shaped with a boring variable name, or a
# boring-looking value assigned to a credential-shaped name).
CREDENTIAL_KEY_NAME_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth|credential)s?\b"
)

# What an env-var *reference* (as opposed to a literal value) looks like
# across the config shapes the tool scans -- YAML/shell/JSON/JS/Python.
ENV_REF_PATTERN = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*\}"          # ${VAR}
    r"|\$[A-Za-z_][A-Za-z0-9_]*"              # $VAR
    r"|os\.environ(?:\.get)?\s*\(?\s*[\"']"   # os.environ["VAR"] / os.environ.get("VAR")
    r"|process\.env\.[A-Za-z_][A-Za-z0-9_]*"  # process.env.VAR
)
