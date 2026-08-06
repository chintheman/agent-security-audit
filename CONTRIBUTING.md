# Contributing

## Adding a new check to an existing checker

1. Add the `check_id` to that module's `CHECK_IDS` list (format:
   `"<category>.<snake_case_name>"`).
2. Write a `_check_<name>(manifest, root)` (or `(manifest, root, context)`
   if it needs cross-cutting input) function that returns a `list[Finding]`.
3. Wire it into that module's `run()`.
4. Every `Finding` you emit **must** set both `fix` and `fix_time_estimate`
   to something concrete — `tests/report/test_model.py::TestFixGuidanceNeverMissing`
   runs every registered checker against a real fixture and fails if any
   finding has empty fix guidance.
5. Never put a raw secret value in `Evidence` — use `asa/redact.py`'s
   `evidence_dict()`/`make_snippet()` helpers, which handle masking and
   hashing for you. `tests/report/test_no_secret_leakage.py` plants real
   secret-shaped values and greps every renderer's output for them; it
   will catch a leak from a new checker too.
6. Add tests under `tests/checkers/test_<module>.py` — at minimum: the
   check fires on a fixture that should trigger it, doesn't fire on one
   that shouldn't (false-positive containment), and doesn't fire on
   `tests/fixtures/clean_project/`.
7. Run `python3 -m unittest discover -s tests -p "test_*.py"` — all of it,
   not just your new tests. Several real bugs during this project's own
   build were caught by the *existing* suite breaking after an unrelated
   change (a regex fix in `redact.py` affected the secrets checker; a
   manifest completeness-contract fix affected every checker's tests).

## Adding a brand-new checker module (new category)

There are six categories already (`asa/finding.py::Category`). A new
category is a bigger decision than a new check — open an issue first. If
you're adding a new *check within an existing category*, see above; that's
almost always what you want.

If a new category is genuinely warranted:

1. Add the value to `Category` in `asa/finding.py`.
2. Create `asa/checkers/<name>.py` implementing the contract in
   `asa/checkers/base.py`: module-level `CATEGORY`, `CHECK_IDS`,
   `activates(manifest) -> bool`, `run(manifest, root, context=None) -> list[Finding]`.
   Checkers are plain-function modules, not classes — match the existing
   ones' style.
3. Register it in `asa/checkers/__init__.py`'s `CHECKER_MODULES` list —
   this is the single, explicit, reviewable point of truth for what runs.
   Nothing is auto-discovered by directory scan on purpose.
4. If the checker needs a new stack signature (a new file/directory
   pattern to recognize), add it to `asa/data/signatures.py`'s
   `SIGNATURES` table — one matcher function, one table entry. Don't add
   detection logic inline in the checker itself.
5. If you touch `asa/ssh_remote.py`'s bundle list, the new module needs to
   go in `_PRE_REGISTRY_MODULES` (or `_POST_REGISTRY_MODULES` if it
   genuinely needs `asa.registry` to exist first) — see that file's
   comments on why ordering matters.

## Standing rules that don't change without a very deliberate reason

- **`asa/fixer.py`'s `SAFE_FIX_ALLOWLIST` stays chmod-only, files only,
  permanently.** No key rotation, no git operations, no file deletion, no
  network calls, no service restarts — regardless of how safe a new fix
  might seem. If you think something belongs there, open an issue and
  make the case; don't just add it.
- **No live credential verification.** This tool never calls out to check
  whether a discovered key actually works. That's a deliberate v1
  boundary — the target audience is strangers whose safe-call/never-call
  judgment calls we can't personally curate the way the original audit
  did. `--allow-audit-tools` (npm audit/pip-audit) and `--ai` are the only
  two outbound-call exceptions, both explicit opt-ins, both documented in
  the README.
- **Never print, log, or send a secret value.** Not the whole value, not
  a prefix, not a suffix. `variable_name` + `value_length` + `value_hash8`
  (first 8 hex chars of SHA-256) is the pattern everywhere in this
  codebase — follow it.
- **`asa/redact.py` never shells out** (no `subprocess` call to `sed`,
  `grep`, or anything else for masking). It uses Python's own `re` and
  `str.replace`. This exists because of a real incident: a masking regex
  using `\s` silently failed to match under BSD `sed` on macOS, and a real
  secret got printed as a result. `tests/test_redact.py` has a named
  regression test for this — don't remove it, and don't reintroduce a
  shell-out for text processing anywhere that touches a value that might
  be a secret.

## Running the test suite

```
python3 -m unittest discover -s tests -p "test_*.py" -v
```

CI runs this across Python 3.9–3.12 on both Ubuntu and macOS — the macOS
leg specifically exists because of the BSD-tool platform-gap lesson above,
even though `redact.py` no longer shells out at all; it's a standing guard
against a future change reintroducing that class of bug.

## Whole-pipeline smoke test

```
python3 scripts/run_selftest.py
```

Runs the real CLI against `tests/fixtures/clean_project` (expects zero
findings) and `tests/fixtures/selftest_project` (expects specific
check_ids to fire) — catches integration regressions unit tests on
individual modules wouldn't, like a checker silently dropping out of the
registry.
