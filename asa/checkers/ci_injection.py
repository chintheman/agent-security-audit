"""GitHub Actions injection-pattern checks. Five checks, drawn from a real
fix applied during the audit this tool is built from (toto-backend):
  1. script_injection_in_run_block -- ${{ github.event.* }} interpolated
     directly into a `run:` shell block instead of via `env:`
  2. script_injection_in_github_script -- same pattern in an
     actions/github-script `with.script:` body
  3. injection_with_high_privilege_secret_in_scope -- escalates 1/2 to
     CRITICAL when a high-privilege secret is referenced in the same file
  4. pull_request_target_with_untrusted_checkout
  5. action_pinned_by_mutable_tag -- @v4 instead of a commit SHA
  6. overly_broad_github_token_permissions -- no permissions: block, or write-all

No YAML parser dependency (stays stdlib-only) -- uses an indentation-aware
block-scalar extractor good enough for the conventional structure real
workflow files use. This is a heuristic, not a full YAML AST; findings from
it are still marked confidence="high" for the interpolation checks (the
regex pattern itself is unambiguous wherever it fires) and "medium" for the
permissions/pin checks (more structurally assumption-dependent).
"""

from __future__ import annotations

import os
import re

from asa.finding import Category, Evidence, Finding, Severity

CATEGORY = Category.CI
CHECK_IDS = [
    "ci.script_injection_in_run_block",
    "ci.script_injection_in_github_script",
    "ci.injection_with_high_privilege_secret_in_scope",
    "ci.pull_request_target_with_untrusted_checkout",
    "ci.action_pinned_by_mutable_tag",
    "ci.overly_broad_github_token_permissions",
]

EVENT_INTERPOLATION = re.compile(r"\$\{\{\s*(github\.event\.[a-zA-Z0-9_.]+|github\.head_ref)\s*\}\}")
HIGH_PRIV_SECRET_NAME = re.compile(r"(?i)(service_role|admin|root|master|SUPABASE_SERVICE_ROLE_KEY|AWS_SECRET_ACCESS_KEY)")
SECRETS_REF = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def activates(manifest) -> bool:
    return manifest.has_kind("github_actions")


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _extract_key_regions(lines: list, key: str):
    """Yields (start_line_no, text) for every `key:` occurrence -- either
    the same-line scalar value, or the indented block that follows a
    block-scalar (`key: |` / `key: >`).

    Handles the `key:` appearing as a YAML list item (`- run: ...`, the
    normal shape of a workflow step) as well as a plain mapping key --
    `indent` is measured to the START OF THE KEY ITSELF (after any leading
    "- "), which is what continuation-line dedent detection needs."""
    pattern = re.compile(rf"^(\s*(?:-\s+)?){re.escape(key)}:\s*(.*)$")
    i = 0
    while i < len(lines):
        m = pattern.match(lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group(1))
        rest = m.group(2).strip()
        start_line = i + 1
        if rest and not rest.startswith(("|", ">")):
            yield start_line, rest
            i += 1
            continue
        # block scalar: collect subsequent more-indented lines
        block_lines = []
        j = i + 1
        while j < len(lines):
            if lines[j].strip() == "":
                block_lines.append(lines[j])
                j += 1
                continue
            if _indent_of(lines[j]) > indent:
                block_lines.append(lines[j])
                j += 1
            else:
                break
        yield start_line, "\n".join(block_lines)
        i = j


def _check_run_block_injection(rel_path: str, content: str, lines: list) -> list:
    findings = []
    for start_line, text in _extract_key_regions(lines, "run"):
        m = EVENT_INTERPOLATION.search(text)
        if m:
            line_offset = text[: m.start()].count("\n")
            findings.append(Finding(
                check_id="ci.script_injection_in_run_block",
                category=CATEGORY, severity=Severity.HIGH,
                title=f"Untrusted input ({m.group(1)}) interpolated directly into a `run:` shell block",
                evidence=Evidence(file=rel_path, line=start_line + line_offset, snippet=m.group(0)),
                fix="Pass the value through `env:` and reference it as a shell variable (e.g. \"$DRAW_NUMBER\") instead of interpolating ${{ }} directly into the script text.",
                fix_time_estimate="10 min", location=f"{rel_path}:{start_line + line_offset}",
            ))
    return findings


def _check_github_script_injection(rel_path: str, content: str, lines: list) -> list:
    findings = []
    uses_lines = [i for i, l in enumerate(lines) if re.search(r"uses:\s*actions/github-script", l)]
    for idx in uses_lines:
        window_end = min(len(lines), idx + 40)
        window_lines = lines[idx:window_end]
        for start_line, text in _extract_key_regions(window_lines, "script"):
            m = EVENT_INTERPOLATION.search(text)
            if m:
                line_offset = text[: m.start()].count("\n")
                actual_line = idx + start_line + line_offset
                findings.append(Finding(
                    check_id="ci.script_injection_in_github_script",
                    category=CATEGORY, severity=Severity.HIGH,
                    title=f"Untrusted input ({m.group(1)}) interpolated directly into an actions/github-script body",
                    evidence=Evidence(file=rel_path, line=actual_line, snippet=m.group(0)),
                    fix="Pass the value through the step's `env:` and read it via `process.env.NAME` inside the script instead of interpolating ${{ }} into the JS text.",
                    fix_time_estimate="10 min", location=f"{rel_path}:{actual_line}",
                ))
    return findings


def _escalate_if_high_privilege_secret(findings: list, content: str, rel_path: str) -> list:
    secret_names = SECRETS_REF.findall(content)
    high_priv = [n for n in secret_names if HIGH_PRIV_SECRET_NAME.search(n)]
    if not high_priv:
        return findings
    escalated = []
    for f in findings:
        if f.check_id in ("ci.script_injection_in_run_block", "ci.script_injection_in_github_script") and f.severity != Severity.CRITICAL:
            escalated.append(Finding(
                check_id="ci.injection_with_high_privilege_secret_in_scope",
                category=CATEGORY, severity=Severity.CRITICAL,
                title=f"{f.title} -- and this workflow has {', '.join(sorted(set(high_priv)))} in scope",
                evidence=f.evidence,
                fix=f.fix + f" This one is more urgent: {', '.join(sorted(set(high_priv)))} is a high-privilege credential.",
                fix_time_estimate=f.fix_time_estimate, location=f.location,
            ))
        else:
            escalated.append(f)
    return escalated


def _check_pull_request_target(rel_path: str, content: str) -> list:
    if "pull_request_target" not in content:
        return []
    if re.search(r"uses:\s*actions/checkout@", content) and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", content):
        return [Finding(
            check_id="ci.pull_request_target_with_untrusted_checkout",
            category=CATEGORY, severity=Severity.CRITICAL,
            title="pull_request_target checks out the untrusted PR head ref",
            evidence=Evidence(file=rel_path),
            fix="Don't check out github.event.pull_request.head.sha under pull_request_target -- it runs with write-level secrets against attacker-controlled code. Use pull_request (no secrets) or a separate workflow_run step instead.",
            fix_time_estimate="30 min", location=rel_path,
        )]
    return []


def _check_pinned_by_tag(rel_path: str, content: str) -> list:
    findings = []
    for m in re.finditer(r"uses:\s*([^\s@]+)@([^\s#]+)", content):
        action, ref = m.group(1), m.group(2)
        if action.startswith("./") or action.startswith("docker://"):
            continue
        if SHA40.match(ref):
            continue
        findings.append(Finding(
            check_id="ci.action_pinned_by_mutable_tag",
            category=CATEGORY, severity=Severity.LOW,
            title=f"{action} pinned by mutable ref '{ref}' instead of a commit SHA",
            evidence=Evidence(file=rel_path, detail={"action": action, "ref": ref}),
            fix=f"Pin to a full commit SHA: uses: {action}@<40-char-sha>  # {ref}",
            fix_time_estimate="5 min", location=rel_path, confidence="medium",
        ))
    return findings


def _check_permissions_block(rel_path: str, content: str) -> list:
    if re.search(r"^\s*permissions:\s*write-all\s*$", content, re.MULTILINE):
        return [Finding(
            check_id="ci.overly_broad_github_token_permissions",
            category=CATEGORY, severity=Severity.MEDIUM,
            title="Workflow sets permissions: write-all",
            evidence=Evidence(file=rel_path),
            fix="Scope permissions to only what each job needs (e.g. contents: read, pull-requests: write) instead of write-all.",
            fix_time_estimate="10 min", location=rel_path, confidence="medium",
        )]
    if not re.search(r"^\s*permissions:", content, re.MULTILINE):
        return [Finding(
            check_id="ci.overly_broad_github_token_permissions",
            category=CATEGORY, severity=Severity.LOW,
            title="Workflow has no explicit permissions: block",
            evidence=Evidence(file=rel_path),
            fix="Add an explicit permissions: block (e.g. contents: read) so this workflow doesn't inherit whatever the repo/org default GITHUB_TOKEN scope is.",
            fix_time_estimate="5 min", location=rel_path, confidence="medium",
        )]
    return []


def run(manifest, root, context=None) -> list:
    findings = []
    for comp in manifest.components_of("github_actions"):
        comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        for fname in comp.signature_files:
            path = os.path.join(comp_dir, fname)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue
            lines = content.split("\n")
            rel_path = os.path.relpath(path, root) if path.startswith(root) else path

            file_findings = []
            file_findings += _check_run_block_injection(rel_path, content, lines)
            file_findings += _check_github_script_injection(rel_path, content, lines)
            file_findings = _escalate_if_high_privilege_secret(file_findings, content, rel_path)
            file_findings += _check_pull_request_target(rel_path, content)
            file_findings += _check_pinned_by_tag(rel_path, content)
            file_findings += _check_permissions_block(rel_path, content)
            findings += file_findings
    return findings
