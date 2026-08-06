# Security

## How this tool handles your secrets

- **No secret value is ever printed, logged, or written to disk** by this
  tool — not the full value, not a prefix, not a suffix. Findings carry a
  variable name, a byte length, and the first 8 hex characters of a
  SHA-256 hash (for correlating "the same value appears in two places," not
  for reversing it). See `asa/redact.py`.
- **No outbound network call by default, period.** Detection is entirely
  local file/content analysis. The only two exceptions, both explicit
  opt-ins you have to pass on the command line:
  - `--allow-audit-tools` runs your own already-installed `npm audit` /
    `pip-audit`, which contact the npm/PyPI registries.
  - `--ai` sends pre-redacted, non-secret fields to an LLM API using your
    own API key. See `asa/ai_assist.py`'s module docstring for the exact
    fields sent and the redaction guarantee.
- **No live credential verification, ever.** This tool never takes a
  discovered key and calls out to check whether it works. That class of
  check requires a carefully curated safe-call/never-call list per
  provider — appropriate for an audit of your own infrastructure with a
  human in the loop, not for a tool run by strangers against unknown
  targets. If you need that, do it yourself, deliberately, one key at a
  time.
- **Read-only by default.** `asa scan` and `asa report` never modify
  anything. `asa fix` can change file permissions (`chmod`) on a narrow,
  fixed list of finding types — see `asa/fixer.py`'s `SAFE_FIX_ALLOWLIST` —
  and only after you confirm each one (or pass `--yes`). It never rotates
  a key, edits a file's contents, touches git, or deletes anything.
- **Every fix is logged with a literal revert command**, written before
  the change is made, so "reversible" means an actual command you can run,
  not just an adjective.

## Reporting a vulnerability in this tool

If you find a security issue in `agent-security-audit` itself (not a
finding it reports about *your* code — that's the whole point of the
tool) — please open a GitHub issue, or if it's sensitive, email the
maintainer listed in the repository's contact info rather than filing a
public issue.

Please include:
- What you ran and what you expected vs. what happened
- Whether it involves a secret value appearing somewhere it shouldn't
  (that's the highest-priority class of bug for this project)
- Whether it's reproducible with the fixtures in `tests/fixtures/`, or
  needs something specific to your environment

## What this tool will never do

Documented as standing product decisions, not just current limitations —
see `CONTRIBUTING.md` for the full list:

- Never make an outbound call to verify a credential
- Never grow `asa fix`'s allowlist beyond chmod-only, files-only fixes
- Never rotate keys, touch git history, delete files, or restart services
- Never phone home, collect telemetry, or send scan results anywhere you
  didn't explicitly direct them (`--out`, stdout, or your own `--ai` key)
