"""The narrow, permanently-narrow safe-fix mechanism. Three check_ids,
chmod-only, files never directories, no key rotation, no git operations, no
deletion, no network calls, no service restarts -- and this list does not
grow without a very deliberate reason (see CONTRIBUTING.md).

SAFE_FIX_ALLOWLIST is a static dict, not a settable Finding attribute --
`Finding.auto_fixable` (set by checkers, used for report categorization) is
NOT trusted here. This module re-derives fixability from check_id alone,
so a checker bug that mis-sets auto_fixable can never cause an actual file
mutation -- only a report-categorization cosmetic error.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

SAFE_FIX_ALLOWLIST = {
    "secrets.dotenv_world_readable": {"action": "chmod", "target_mode": 0o600},
    "permissions.ssh_private_key_permissive_mode": {"action": "chmod", "target_mode": 0o600},
    "permissions.sensitive_file_world_readable": {"action": "chmod", "target_mode": 0o600},
}


def is_auto_fixable(check_id: str) -> bool:
    return check_id in SAFE_FIX_ALLOWLIST


@dataclass
class FixResult:
    finding_id: str
    check_id: str
    path: str
    action: str
    applied: bool
    old_mode: int = None
    new_mode: int = None
    skipped_reason: str = None

    def to_dict(self) -> dict:
        return asdict(self)


def _default_input(prompt: str) -> str:
    return input(prompt)


def _default_print(msg: str) -> None:
    print(msg)


def apply(findings: list, *, mode: str = "ask-each", input_func=None, print_func=None, log_dir: str = None) -> list:
    """mode: "ask-each" (default, prompts per item) | "dry-run" (prints
    what would happen, applies nothing) | "yes" (applies every fixable
    finding without prompting -- still logged, still chmod-only).

    Refuses findings whose location doesn't currently exist as a regular
    file (never operates on directories, never assumes a stale path is
    still valid) and never touches anything outside SAFE_FIX_ALLOWLIST."""
    input_func = input_func or _default_input
    print_func = print_func or _default_print
    results = []
    apply_all = mode == "yes"

    fixable = [f for f in findings if is_auto_fixable(f.check_id)]
    for f in fixable:
        spec = SAFE_FIX_ALLOWLIST[f.check_id]
        path = f.location

        if not os.path.isfile(path):
            results.append(FixResult(f.id, f.check_id, path, spec["action"], False, skipped_reason="not a regular file (missing, or a directory)"))
            continue
        if os.path.islink(path):
            results.append(FixResult(f.id, f.check_id, path, spec["action"], False, skipped_reason="refusing to chmod a symlink"))
            continue

        try:
            old_mode = os.stat(path).st_mode & 0o777
        except OSError as exc:
            results.append(FixResult(f.id, f.check_id, path, spec["action"], False, skipped_reason=f"could not stat: {exc}"))
            continue

        target_mode = spec["target_mode"]
        command = f"chmod {oct(target_mode)[2:]} {path}"

        if mode == "dry-run":
            print_func(f"[dry-run] {f.title}\n  would run: {command}")
            results.append(FixResult(f.id, f.check_id, path, spec["action"], False, old_mode, skipped_reason="dry-run"))
            continue

        if not apply_all:
            print_func(f"{f.title}\n  {command}")
            answer = input_func("Apply this fix? [y/N/a/q] ").strip().lower()
            if answer == "q":
                break
            if answer == "a":
                apply_all = True
            elif answer != "y":
                results.append(FixResult(f.id, f.check_id, path, spec["action"], False, old_mode, skipped_reason="declined"))
                continue

        try:
            os.chmod(path, target_mode)
        except OSError as exc:
            results.append(FixResult(f.id, f.check_id, path, spec["action"], False, old_mode, skipped_reason=f"chmod failed: {exc}"))
            continue

        results.append(FixResult(f.id, f.check_id, path, spec["action"], True, old_mode, target_mode))

    if log_dir:
        write_fix_log(log_dir, results)
    return results


def write_fix_log(log_dir: str, results: list) -> str:
    os.makedirs(log_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat().replace(":", "-")
    path = os.path.join(log_dir, f"{stamp}-fix-log.json")
    payload = {
        "results": [r.to_dict() for r in results],
        "revert_commands": [
            f"chmod {oct(r.old_mode)[2:]} {r.path}" for r in results if r.applied and r.old_mode is not None
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path
