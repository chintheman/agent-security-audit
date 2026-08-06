"""Agent/AI-tool blast-radius checks. Four checks -- the last checker,
deliberately, because it deals with the most varied and least-standardized
config shapes (every agent harness has its own settings format). Checks 1
and 2 are deterministic and high-confidence; checks 3 and 4 are heuristic
keyword-matches over config text and are marked lower confidence rather
than pretending to a precision they don't have.

  1. broad_bash_allowlist -- Bash(*)-shaped permission grants
  2. unpinned_mcp_latest_invocation -- `npx -y pkg` / `pkg@latest`
  3. no_interactive_vs_unattended_separation -- a cron/scheduled profile
     with the same broad tool scope as an interactive one (heuristic)
  4. prompt_injection_reachability -- untrusted-input tool + high-impact
     tool in the same config, no visible approval-gate marker (heuristic)
"""

from __future__ import annotations

import json
import os
import re

from asa.finding import Category, Evidence, Finding, Severity

CATEGORY = Category.AGENT
CHECK_IDS = [
    "agent.broad_bash_allowlist",
    "agent.unpinned_mcp_latest_invocation",
    "agent.no_interactive_vs_unattended_separation",
    "agent.prompt_injection_reachability",
]

BROAD_BASH_PATTERNS = {"Bash", "Bash(*)", "Bash(**)"}

UNTRUSTED_INPUT_KEYWORDS = re.compile(
    r"(?i)\b(web[_-]?fetch|read[_-]?webpage|browse|web[_-]?search|gmail|email|"
    r"telegram|read[_-]?url|http[_-]?request|fetch[_-]?url|rss|news[_-]?feed)\b"
)
HIGH_IMPACT_KEYWORDS = re.compile(
    r"(?i)\b(bash|exec|shell|subprocess|pay|transfer|withdraw|trade|order|"
    r"publish|delete|send[_-]?message|send[_-]?email|financial)\b"
)
APPROVAL_MARKERS = re.compile(r"(?i)\b(requireConfirmation|require_confirmation|approval|confirm|ask[_-]?before)\b")
SCHEDULE_MARKERS = re.compile(r"(?i)\b(cron|schedule|scheduled|every_\w+|interval)\b")


def activates(manifest) -> bool:
    return manifest.has_kind("claude_code_config") or manifest.has_kind("mcp_config") or manifest.has_kind("hermes_profile")


def _load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _check_broad_bash_allowlist(manifest, root) -> list:
    findings = []
    for comp in manifest.components_of("claude_code_config"):
        if "settings.json" not in comp.signature_files:
            continue
        comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        path = os.path.join(comp_dir, "settings.json")
        data = _load_json(path)
        if not isinstance(data, dict):
            continue
        allow = data.get("permissions", {}).get("allow", []) if isinstance(data.get("permissions"), dict) else []
        rel = os.path.relpath(path, root) if path.startswith(root) else path
        for entry in allow:
            if entry in BROAD_BASH_PATTERNS:
                findings.append(Finding(
                    check_id="agent.broad_bash_allowlist",
                    category=CATEGORY, severity=Severity.HIGH,
                    title=f"Overly broad shell permission grant: '{entry}'",
                    evidence=Evidence(file=rel, snippet=entry),
                    fix="Scope Bash permissions to specific command prefixes (e.g. \"Bash(git *)\") instead of granting all shell access.",
                    fix_time_estimate="10 min", location=rel,
                ))
    return findings


def _iter_mcp_server_specs(manifest, root):
    for kind in ("claude_code_config", "mcp_config"):
        for comp in manifest.components_of(kind):
            for fname in comp.signature_files:
                comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
                path = os.path.join(comp_dir, fname)
                data = _load_json(path)
                if not isinstance(data, dict):
                    continue
                servers = data.get("mcpServers", {})
                if isinstance(servers, dict):
                    for name, spec in servers.items():
                        yield path, name, spec


def _check_unpinned_mcp(manifest, root) -> list:
    findings = []
    for path, name, spec in _iter_mcp_server_specs(manifest, root):
        if not isinstance(spec, dict):
            continue
        command = spec.get("command", "")
        args = spec.get("args", [])
        if command != "npx" or not isinstance(args, list):
            continue
        if "-y" not in args:
            continue
        pkg_args = [a for a in args if isinstance(a, str) and not a.startswith("-") and a != "npx"]
        for pkg in pkg_args:
            if pkg.endswith("@latest") or "@" not in pkg.lstrip("@"):
                rel = os.path.relpath(path, root) if path.startswith(root) else path
                findings.append(Finding(
                    check_id="agent.unpinned_mcp_latest_invocation",
                    category=CATEGORY, severity=Severity.MEDIUM,
                    title=f"MCP server '{name}' runs an unpinned package ({pkg}) with full tool privileges",
                    evidence=Evidence(file=rel, variable_name=name, snippet=pkg),
                    fix=f"Pin to a specific version, e.g. \"{pkg.split('@')[0]}@x.y.z\" -- unpinned means remote code is fetched fresh on every launch.",
                    fix_time_estimate="5 min", location=rel,
                ))
    return findings


def _check_unattended_separation(manifest, root) -> list:
    findings = []
    for comp in manifest.components_of("hermes_profile"):
        comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        for dirpath, _, filenames in os.walk(comp_dir):
            for fname in filenames:
                if not fname.endswith((".yaml", ".yml", ".md")):
                    continue
                path = os.path.join(dirpath, fname)
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue
                if SCHEDULE_MARKERS.search(content) and HIGH_IMPACT_KEYWORDS.search(content):
                    rel = os.path.relpath(path, root) if path.startswith(root) else path
                    findings.append(Finding(
                        check_id="agent.no_interactive_vs_unattended_separation",
                        category=CATEGORY, severity=Severity.MEDIUM,
                        title=f"{fname} looks scheduled/unattended and references high-impact tool capability in the same file",
                        evidence=Evidence(file=rel),
                        fix="Confirm this cron-triggered profile has a narrower tool scope than an interactive session would -- an unattended run has no human to catch a bad action.",
                        fix_time_estimate="15 min", location=rel, confidence="low",
                    ))
    return findings


def _check_prompt_injection_reachability(manifest, root) -> list:
    findings = []
    seen_paths = set()
    candidates = []
    for path, name, spec in _iter_mcp_server_specs(manifest, root):
        candidates.append(path)
    for comp in manifest.components_of("claude_code_config"):
        comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        for fname in comp.signature_files:
            candidates.append(os.path.join(comp_dir, fname))

    for path in set(candidates):
        if path in seen_paths:
            continue
        seen_paths.add(path)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        has_untrusted = bool(UNTRUSTED_INPUT_KEYWORDS.search(content))
        has_high_impact = bool(HIGH_IMPACT_KEYWORDS.search(content))
        has_approval = bool(APPROVAL_MARKERS.search(content))
        if has_untrusted and has_high_impact and not has_approval:
            rel = os.path.relpath(path, root) if path.startswith(root) else path
            findings.append(Finding(
                check_id="agent.prompt_injection_reachability",
                category=CATEGORY, severity=Severity.MEDIUM,
                title=f"{os.path.basename(path)} grants both an untrusted-input tool and a high-impact tool with no visible approval gate",
                evidence=Evidence(file=rel),
                fix="Add an approval/confirmation step before the high-impact tool can act on anything derived from untrusted input (web content, email, messages), or split them into separate, more narrowly-scoped configs.",
                fix_time_estimate="20 min", location=rel, confidence="low",
            ))
    return findings


def run(manifest, root, context=None) -> list:
    findings = []
    findings += _check_broad_bash_allowlist(manifest, root)
    findings += _check_unpinned_mcp(manifest, root)
    findings += _check_unattended_separation(manifest, root)
    findings += _check_prompt_injection_reachability(manifest, root)
    return findings
