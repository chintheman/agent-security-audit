"""Optional --ai hook. Lazy-imported only inside the --ai code path in
cli.py -- the base tool has zero required third-party dependencies, and
this module keeps that true by using stdlib `urllib.request` directly
rather than an Anthropic/OpenAI SDK (a deliberate, documented improvement
over the plan's literal "optional SDK dependency" -- no dependency to
install or pin at all for this feature to work).

Two narrow call sites. Deterministic checks remain authoritative in both:

1. classify_unknown_component() -- the manifest's signature table is
   necessarily incomplete (new frameworks appear constantly); this helps
   identify a directory with config-like files that matched no known
   signature. Live trigger: cli.py calls find_unrecognized_directories()
   after every scan when --ai is set.

2. suggest_fix() -- fix-phrasing for a Finding with no built-in fix text.
   Honest scope note: every checker in this tool's current 6 categories is
   required (enforced by tests/report/test_model.py::TestFixGuidanceNeverMissing)
   to always populate Finding.fix itself, so under the CURRENT checker set
   this call site has no live trigger -- it exists, is fully tested, and
   engages automatically the moment any checker (built-in or
   community-contributed) ever emits a Finding with empty fix text, without
   needing further wiring.

Hard invariant, enforced in code not just by convention: _build_prompt()
runs every string field through redact.assert_no_secret_shape() immediately
before constructing the API request. This is on top of callers only ever
passing already-redacted fields -- belt and suspenders.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from asa import redact
from asa.data.signatures import VENDORED_DIR_NAMES

CONFIG_LIKE_EXTENSIONS = {".yml", ".yaml", ".toml", ".json", ".conf", ".cfg", ".ini", ".tf", ".tfvars"}
MAX_SAMPLE_CHARS_PER_FILE = 800

DEFAULT_MODELS = {
    "anthropic": "claude-3-5-haiku-20241022",
    "openai": "gpt-4o-mini",
}


class AIAssistError(RuntimeError):
    """Raised on missing config, a request failure, or a response that
    can't be parsed -- callers decide whether to fall back or surface it."""


def _provider_and_key():
    provider = os.environ.get("ASA_LLM_PROVIDER", "anthropic")
    api_key = os.environ.get("ASA_LLM_API_KEY")
    if not api_key:
        raise AIAssistError("ASA_LLM_API_KEY is not set -- --ai requires your own API key.")
    if provider not in DEFAULT_MODELS:
        raise AIAssistError(f"unknown ASA_LLM_PROVIDER {provider!r} -- expected 'anthropic' or 'openai'")
    model = os.environ.get("ASA_LLM_MODEL", DEFAULT_MODELS[provider])
    return provider, api_key, model


def _build_prompt(template: str, **fields) -> str:
    """The hard choke point: every field value is checked for
    credential-shaped substrings immediately before being interpolated
    into the outgoing prompt. Raises rather than silently stripping --
    a caller that hits this has a bug upstream (it should never have
    passed unredacted content in the first place)."""
    for name, value in fields.items():
        redact.assert_no_secret_shape(str(value))
    return template.format(**fields)


def _call_anthropic(api_key: str, model: str, prompt: str, max_tokens: int) -> str:
    body = json.dumps({
        "model": model, "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body, method="POST",
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise AIAssistError(f"Anthropic API request failed: {exc}") from exc
    try:
        return data["content"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise AIAssistError(f"unexpected Anthropic API response shape: {exc}") from exc


def _call_openai(api_key: str, model: str, prompt: str, max_tokens: int) -> str:
    body = json.dumps({
        "model": model, "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions", data=body, method="POST",
        headers={"Authorization": f"Bearer {api_key}", "content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise AIAssistError(f"OpenAI API request failed: {exc}") from exc
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise AIAssistError(f"unexpected OpenAI API response shape: {exc}") from exc


def _call_llm(prompt: str, max_tokens: int = 400) -> str:
    provider, api_key, model = _provider_and_key()
    if provider == "anthropic":
        return _call_anthropic(api_key, model, prompt, max_tokens)
    return _call_openai(api_key, model, prompt, max_tokens)


# --- call site 1: unrecognized component classification -------------------

def find_unrecognized_directories(manifest, root: str, max_dirs: int = 5) -> list:
    """Directories containing config-like files that matched no known
    Signature. Capped at max_dirs -- this is a hint list for --ai, not a
    full audit; log() the cap at the call site so it's never a silent
    truncation."""
    known_roots = {c.root for c in manifest.components}
    candidates = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        for d in list(dirnames):
            if d in VENDORED_DIR_NAMES or d.endswith(".egg-info"):
                dirnames.remove(d)
        rel = os.path.relpath(dirpath, root)
        if rel in known_roots:
            continue
        config_files = [f for f in filenames if os.path.splitext(f)[1] in CONFIG_LIKE_EXTENSIONS]
        if config_files:
            candidates.append({"path": dirpath, "rel": rel, "sample_files": sorted(config_files)[:5]})
        if len(candidates) >= max_dirs:
            break
    return candidates


def _sample_content(dirpath: str, filenames: list) -> dict:
    samples = {}
    for fname in filenames:
        path = os.path.join(dirpath, fname)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(MAX_SAMPLE_CHARS_PER_FILE)
        except OSError:
            continue
        # input-side redaction, on top of whatever the caller already did --
        # this is content read directly from disk, not yet vetted at all.
        samples[fname] = redact.mask_credential_shapes(text)
    return samples


_CLASSIFY_TEMPLATE = """You are classifying an unrecognized directory found during a security audit tool's stack-detection pass. Based on the filenames and file contents below, guess what kind of project/component this is (e.g. "rust_project", "terraform_config", "helm_chart"). Respond with ONLY a JSON object, no other text: {{"kind_guess": "<short_snake_case_kind>", "confidence": "low"|"medium", "rationale": "<one sentence>"}}

Directory: {dirpath}
Files: {filenames}

Sample content:
{samples}
"""


def classify_unknown_component(dirpath: str, filenames: list) -> dict:
    """Returns {"kind_guess", "confidence", "rationale"}. Confidence is
    capped at "medium" regardless of what the model claims -- an
    AI-suggested classification can never claim "high"."""
    samples = _sample_content(dirpath, filenames)
    samples_text = "\n\n".join(f"--- {name} ---\n{content}" for name, content in samples.items())
    prompt = _build_prompt(
        _CLASSIFY_TEMPLATE, dirpath=dirpath, filenames=", ".join(filenames), samples=samples_text,
    )
    raw = _call_llm(prompt)
    try:
        parsed = json.loads(raw.strip().strip("`").removeprefix("json").strip())
    except (ValueError, AttributeError):
        return {"kind_guess": "unknown", "confidence": "low", "rationale": "could not parse AI response"}
    return {
        "kind_guess": str(parsed.get("kind_guess", "unknown")),
        "confidence": "medium" if parsed.get("confidence") in ("medium", "high") else "low",
        "rationale": str(parsed.get("rationale", ""))[:300],
    }


# --- call site 2: fix-phrasing for a check with no built-in fix text ------

_FIX_TEMPLATE = """A security audit tool found this issue but has no built-in fix suggestion for it. Suggest a concise, concrete fix in one short paragraph (2-3 sentences max). Do not ask for more information -- give your best recommendation given what's here.

Category: {category}
Check: {check_id}
Title: {title}
File: {file}
Variable name: {variable_name}
"""


def suggest_fix(finding_stub: dict) -> str:
    """finding_stub must be pre-stripped to {category, check_id, title,
    file, variable_name} -- never raw content, never Evidence.snippet.
    Caller is responsible for setting the resulting Finding's
    source="ai-assist" and confidence to no higher than "medium"."""
    prompt = _build_prompt(
        _FIX_TEMPLATE,
        category=finding_stub.get("category", ""),
        check_id=finding_stub.get("check_id", ""),
        title=finding_stub.get("title", ""),
        file=finding_stub.get("file", ""),
        variable_name=finding_stub.get("variable_name", ""),
    )
    return _call_llm(prompt).strip()
