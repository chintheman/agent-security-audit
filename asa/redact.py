"""Secret-shape detection + masking + hashing. Single source of truth for
redaction -- every checker and every report renderer goes through this
module rather than re-implementing masking locally.

Design rule, non-negotiable: masking here NEVER shells out to `sed`,
`grep`, or any external text-processing tool. It uses only Python's own
`str.replace` (for masking a KNOWN value -- literal substring match, immune
to regex-metacharacter and locale/whitespace-semantics issues) and
Python's own `re` module (for detecting credential-SHAPED substrings whose
exact value isn't already known). This exists because of a real incident:
a masking regex using `\\s` silently failed to match under BSD sed on
macOS, and a real secret was printed as a result. Python's `re` module
doesn't have that platform-specific behavior gap -- see
tests/test_redact.py for the regression test.
"""

from __future__ import annotations

import hashlib

from asa.data.secret_patterns import CREDENTIAL_SHAPE_PATTERNS


class SecretShapeDetected(ValueError):
    """Raised by assert_no_secret_shape when a credential-shaped substring
    is found in text that must not contain one (e.g. an ai_assist.py
    prompt payload)."""


def hash8(value: str) -> str:
    """First 8 hex chars of sha256(value). Correlation/dedup only -- never
    used to reconstruct or verify the original value."""
    return hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()[:8]


def mask_literal(text: str, value: str, name: str | None = None) -> str:
    """Replace every literal occurrence of `value` in `text` with a
    redaction placeholder. Uses str.replace, NOT a regex built from
    `value` -- so a value containing regex metacharacters (., *, $, etc.)
    is handled correctly instead of corrupting the pattern or silently
    failing to match."""
    if not value:
        return text
    placeholder = f"<redacted:{name}:len={len(value)}>" if name else f"<redacted:len={len(value)}>"
    return text.replace(value, placeholder)


def find_credential_shapes(text: str) -> list[tuple[str, int, int, str]]:
    """Scan text for known credential shapes. Returns (pattern_name, start,
    end, matched_substring) tuples. Used internally by mask_credential_shapes
    and assert_no_secret_shape -- not intended to surface matched_substring
    to any report or log; callers must only use it for masking/detection,
    never for display."""
    hits: list[tuple[str, int, int, str]] = []
    for name, pattern in CREDENTIAL_SHAPE_PATTERNS:
        for m in pattern.finditer(text):
            hits.append((name, m.start(), m.end(), m.group(0)))
    return hits


def mask_credential_shapes(text: str) -> str:
    """Mask every credential-shaped substring found in text, regardless of
    whether the caller already knows a specific secret value to mask. Used
    to redact snippets/content that may contain secrets the checker wasn't
    specifically looking for (e.g. a second, unrelated key on the same
    line)."""
    masked = text
    for name, pattern in CREDENTIAL_SHAPE_PATTERNS:
        masked = pattern.sub(lambda m, n=name: f"<redacted:{n}>", masked)
    return masked


def assert_no_secret_shape(text: str) -> None:
    """Raise SecretShapeDetected if text contains any credential-shaped
    substring. This is the hard choke point ai_assist.py runs every
    outbound string through immediately before an API call -- belt and
    suspenders on top of only ever passing already-redacted fields."""
    hits = find_credential_shapes(text)
    if hits:
        names = ", ".join(sorted({h[0] for h in hits}))
        raise SecretShapeDetected(
            f"refusing to send text containing credential-shaped substring(s): {names}"
        )


def make_snippet(text: str, known_value: str | None = None, max_len: int = 160) -> str:
    """Build a report-safe snippet from a line of source text: mask a known
    secret value first (if given), then mask any OTHER credential-shaped
    substrings that happen to be on the same line, then truncate. This is
    the only function checkers should use to populate Evidence.snippet."""
    result = text
    if known_value:
        result = mask_literal(result, known_value)
    result = mask_credential_shapes(result)
    result = result.strip()
    if len(result) > max_len:
        result = result[: max_len].rstrip() + "…"
    return result


def evidence_dict(
    *,
    value: str,
    file: str | None = None,
    line: int | None = None,
    variable_name: str | None = None,
    raw_line: str | None = None,
    detail: dict | None = None,
) -> dict:
    """Convenience builder for the fields of an Evidence record, given a
    raw secret value that must never itself be stored or returned. Checkers
    should prefer this over hand-assembling Evidence so redaction can't be
    accidentally skipped. Returns a plain dict matching Evidence's
    constructor kwargs (file, line, variable_name, value_length,
    value_hash8, snippet, detail)."""
    return {
        "file": file,
        "line": line,
        "variable_name": variable_name,
        "value_length": len(value) if value else None,
        "value_hash8": hash8(value) if value else None,
        "snippet": make_snippet(raw_line, known_value=value) if raw_line else None,
        "detail": detail or {},
    }
