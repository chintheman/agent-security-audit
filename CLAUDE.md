# Working in this repo

Conventions for an AI-assisted session (or a human) picking this codebase
up cold. See `CONTRIBUTING.md` for the step-by-step "how to add a check"
guide — this file is the shorter "what you need to know before you start
editing" version.

## The shape of the codebase

- **Checkers are plain-function modules**, not classes. Each one under
  `asa/checkers/` exports `CATEGORY`, `CHECK_IDS`, `activates(manifest)`,
  `run(manifest, root, context=None)`. `asa/checkers/__init__.py`'s
  `CHECKER_MODULES` list is the one explicit, reviewable place that says
  what runs — there's no directory-scan auto-discovery, on purpose.
- **`asa/redact.py` is the single source of truth for secret handling.**
  Every checker uses `redact.evidence_dict()` / `redact.make_snippet()` to
  build `Evidence` — never hand-assemble one with a raw value in it.
  `tests/report/test_no_secret_leakage.py` is a black-box check that
  plants real secret-shaped values and greps every renderer's output for
  them; it will catch a new leak, but the cheap way to avoid needing that
  safety net is to always go through `redact.py`.
- **`asa/manifest.py`'s completeness contract is load-bearing, not
  decorative.** `Manifest.verify_completeness()` compares against a
  point-in-time `top_level_snapshot` captured at scan time — it does NOT
  re-list the live directory. Two real bugs shipped and got caught by
  tests before release specifically because this was gotten wrong once: a
  plain file matching no stack signature was treated as an "unaccounted
  gap" (wrong — it was legitimately walked and found clean), and a live
  re-list saw the tool's own `asa-output/` write as a fresh gap on the
  very next check. If you touch `manifest.py`, re-read those two
  incidents in the git history (search "completeness" in commit messages)
  before changing the semantics again.
- **Every `Finding.fix` and `Finding.fix_time_estimate` must be
  non-empty.** Enforced by `tests/report/test_model.py::TestFixGuidanceNeverMissing`,
  which runs every registered checker against a real fixture. This is a
  deliberate substitute for what an earlier draft of the design called a
  separate `FIX_NEXT_STEP_TEMPLATES` table — the per-instance fix text
  checkers already produce is richer, so there's no second source of
  truth to keep in sync.
- **`asa/fixer.py` re-derives fixability from `check_id`, never trusts
  `Finding.auto_fixable`.** That field exists for report categorization
  only (`report/model.py`'s "Need You" list). A checker bug that
  mis-sets it can never cause an actual file mutation — verified by
  `tests/test_fixer.py::TestSafetyGuards::test_ignores_finding_field_auto_fixable_override`,
  which deliberately constructs a lying Finding and confirms it's ignored.

## Testing discipline that's paid off repeatedly during this project's build

- **Run the real CLI, not just unit tests, before considering a milestone
  done.** Nearly every "real bug, not a test bug" caught during this
  project's build (see commit history — M2 through M9 each found at least
  one) was caught by actually invoking `python3 -m asa scan ...` against a
  throwaway fixture, not by the unit tests passing. Unit tests prove a
  function does what you told it to; running the CLI proves the pieces
  actually fit together.
- **When a test fails, figure out which side is wrong before "fixing"
  it.** More than once during this build, a failing test turned out to be
  a bad fixture (a word-built fake password that collided with ordinary
  English prose in the leak-detection test; a fixture using a filename
  pattern the checker was never meant to recognize) rather than a bug in
  the implementation. Fixing the wrong side hides a real bug in the
  ai_assist.py redaction choke point once actually caught a genuine,
  significant regex bug (`generic_high_entropy_hex_or_b64` matched
  straight through filesystem paths) — that only surfaced because the
  test's *purpose* (never send an unredacted path to an LLM) was taken
  seriously enough to investigate rather than loosen.
- **`python3 scripts/run_selftest.py`** is the fastest whole-pipeline
  sanity check — faster than reasoning about whether a change to
  `registry.py` or `runner.py` broke checker wiring.

## What NOT to add without opening an issue first

See `SECURITY.md` / `CONTRIBUTING.md`'s "standing rules" section: no live
credential verification, no growing `fixer.py`'s allowlist past
chmod-only, no new outbound-call paths beyond the two already-documented
opt-ins (`--allow-audit-tools`, `--ai`).
