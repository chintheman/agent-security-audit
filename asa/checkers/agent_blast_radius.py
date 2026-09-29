"""Agent/AI-tool blast-radius checks. Six checks -- the last checker,
deliberately, because it deals with the most varied and least-standardized
config shapes (every agent harness has its own settings format). Checks 1
and 2 are deterministic and high-confidence; checks 3-6 are heuristic
keyword-matches over config text and are marked lower confidence rather
than pretending to a precision they don't have.

  1. broad_bash_allowlist -- Bash(*)-shaped permission grants
  2. unpinned_mcp_latest_invocation -- `npx -y pkg` / `pkg@latest`
  3. no_interactive_vs_unattended_separation -- a cron/scheduled profile
     with the same broad tool scope as an interactive one (heuristic)
  4. prompt_injection_reachability -- untrusted-input tool + high-impact
     tool in the same config, no visible approval-gate marker (heuristic)
  5. exfiltration_triad -- private-data access + untrusted-content
     ingestion + an outbound channel, all in the same config (heuristic).
     A stricter, three-condition sibling of check 4: 4 asks "can bad
     content reach a dangerous tool", 5 asks "can that dangerous tool then
     ship data somewhere" -- gate at least one leg.
  6. trusts_mcp_tool_annotations -- a config that auto-approves or
     blanket-allows a whole MCP server's tools (e.g. a Claude Code
     "mcp__server__*" permission entry), or explicitly conditions
     auto-approval on a server-declared tool annotation (readOnlyHint,
     destructiveHint, idempotentHint) -- both self-reported by the server,
     never verified by the client.
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
    "agent.exfiltration_triad",
    "agent.trusts_mcp_tool_annotations",
]

BROAD_BASH_PATTERNS = {"Bash", "Bash(*)", "Bash(**)"}

# Same size guard secrets.py/network.py apply before reading a file whole
# -- an agent config is normally tiny, but a hermes_profile directory can
# contain arbitrary text-ish files, so this skips anything unreasonably
# large rather than reading it in one go.
MAX_AGENT_CONFIG_SCAN_BYTES = 1_000_000

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

# --- exfiltration triad: three independent legs, all three required ---
PRIVATE_DATA_KEYWORDS = re.compile(
    r"(?i)\b(filesystem|file[_-]?system|read[_-]?file|write[_-]?file|local[_-]?file|"
    r"secrets?|credential|dotenv|private[_-]?key|ssh[_-]?key|keychain|"
    r"gmail|imap|mailbox|inbox|"
    r"database|db[_-]?query|postgres|mysql|sqlite|\bsql\b)\b"
)
UNTRUSTED_CONTENT_KEYWORDS = re.compile(
    r"(?i)\b(web[_-]?fetch|fetch[_-]?url|read[_-]?url|browse|web[_-]?search|"
    r"read[_-]?webpage|rss|news[_-]?feed|"
    r"issue[_-]?comment|pr[_-]?comment|pull[_-]?request[_-]?comment|"
    r"email|read[_-]?email|incoming[_-]?email)\b"
)
OUTBOUND_CHANNEL_KEYWORDS = re.compile(
    r"(?i)\b(http[_-]?post|send[_-]?request|webhook|"
    r"send[_-]?email|email[_-]?send|smtp|"
    r"send[_-]?message|send[_-]?sms|telegram|slack|discord|"
    r"bash|shell|subprocess|exec)\b"
)

# --- trusts_mcp_tool_annotations ---
MCP_BLANKET_SERVER_WILDCARD = re.compile(r"^mcp__.+__\*$")

# Server-declared MCP tool annotations (self-reported, never verified by
# the client) -- see https://modelcontextprotocol.io tool annotation spec.
ANNOTATION_HINT_NAMES = ("readOnlyHint", "destructiveHint", "idempotentHint")
_HINT_ALTERNATION = "|".join(ANNOTATION_HINT_NAMES)
_TRUST_WORD_ALTERNATION = r"auto[_-]?approve|allowlist|trust|skip[_-]?confirm|no[_-]?prompt"
ANNOTATION_TRUST_PATTERN = re.compile(
    rf"(?i)(?:(?:{_TRUST_WORD_ALTERNATION})[^\n]{{0,60}}(?:{_HINT_ALTERNATION})"
    rf"|(?:{_HINT_ALTERNATION})[^\n]{{0,60}}(?:{_TRUST_WORD_ALTERNATION}))"
)


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


def _agent_config_candidates(manifest, root) -> list:
    """Shared candidate-file gathering for the config-text heuristic
    checks: every MCP server spec's own file, every claude_code_config
    signature file, and every text-ish file under a hermes_profile
    directory. Mirrors _check_prompt_injection_reachability's gathering,
    extended with hermes_profile so a Hermes profile that combines all
    three exfiltration-triad legs in one file is reachable too."""
    candidates = []
    for path, _name, _spec in _iter_mcp_server_specs(manifest, root):
        candidates.append(path)
    for comp in manifest.components_of("claude_code_config"):
        comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        for fname in comp.signature_files:
            candidates.append(os.path.join(comp_dir, fname))
    for comp in manifest.components_of("hermes_profile"):
        comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        for dirpath, _, filenames in os.walk(comp_dir):
            for fname in filenames:
                if fname.endswith((".yaml", ".yml", ".md", ".json")):
                    candidates.append(os.path.join(dirpath, fname))
    return sorted(set(candidates))


def _read_capped(path: str):
    """Size-capped text read, same guard secrets.py/network.py use before
    reading a file whole -- returns None (skip) for anything unreadable
    or over MAX_AGENT_CONFIG_SCAN_BYTES."""
    try:
        if os.path.getsize(path) > MAX_AGENT_CONFIG_SCAN_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _check_exfiltration_triad(manifest, root) -> list:
    findings = []
    for path in _agent_config_candidates(manifest, root):
        content = _read_capped(path)
        if content is None:
            continue
        has_private = bool(PRIVATE_DATA_KEYWORDS.search(content))
        has_untrusted = bool(UNTRUSTED_CONTENT_KEYWORDS.search(content))
        has_outbound = bool(OUTBOUND_CHANNEL_KEYWORDS.search(content))
        if has_private and has_untrusted and has_outbound:
            rel = os.path.relpath(path, root) if path.startswith(root) else path
            findings.append(Finding(
                check_id="agent.exfiltration_triad",
                category=CATEGORY, severity=Severity.HIGH,
                title=f"{os.path.basename(path)} combines private-data access, untrusted-content ingestion, and an outbound channel",
                evidence=Evidence(file=rel, detail={
                    "has_private_data_access": has_private,
                    "has_untrusted_content_ingestion": has_untrusted,
                    "has_outbound_channel": has_outbound,
                }),
                fix="An agent that can read private data (filesystem/secrets/email/db), ingest untrusted content (web pages, email, issue/PR comments), and send data out (HTTP, email, messaging, webhook, or a shell with network access) can be tricked by the content it reads into exfiltrating what it can access. Gate at least one leg: drop one of the three capabilities from this config, or require human approval before the outbound-channel tool runs on anything derived from untrusted input.",
                fix_time_estimate="20 min", location=rel, confidence="low",
            ))
    return findings


def _check_trusts_mcp_tool_annotations(manifest, root) -> list:
    findings = []
    seen_wildcards = set()

    # Signal 1: a blanket "every tool from this server" (or every MCP tool
    # from every server) allow-wildcard in a Claude-Code-shaped
    # settings.json permissions block. The client can't distinguish a
    # destructive tool from a read-only one inside that wildcard -- it's
    # trusting whatever the server SAYS about its own tools.
    for comp in manifest.components_of("claude_code_config"):
        if "settings.json" not in comp.signature_files:
            continue
        comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        path = os.path.join(comp_dir, "settings.json")
        data = _load_json(path)
        if not isinstance(data, dict):
            continue
        perms = data.get("permissions", {})
        if not isinstance(perms, dict):
            continue
        rel = os.path.relpath(path, root) if path.startswith(root) else path
        for key in ("allow", "alwaysAllow", "autoApprove"):
            entries = perms.get(key, [])
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, str):
                    continue
                if entry != "mcp__*" and not MCP_BLANKET_SERVER_WILDCARD.match(entry):
                    continue
                dedup_key = (rel, entry)
                if dedup_key in seen_wildcards:
                    continue
                seen_wildcards.add(dedup_key)
                scope = "every connected MCP server" if entry == "mcp__*" else f"MCP server '{entry[len('mcp__'):-len('__*')]}'"
                findings.append(Finding(
                    check_id="agent.trusts_mcp_tool_annotations",
                    category=CATEGORY, severity=Severity.MEDIUM,
                    title=f"'{entry}' auto-approves every tool from {scope} with no per-tool review",
                    evidence=Evidence(file=rel, snippet=entry),
                    fix="A wildcard grant like this trusts whatever the server itself claims about each tool's safety (readOnlyHint, destructiveHint, idempotentHint) -- those are self-reported by the server, not verified by the client. Replace the wildcard with an explicit allowlist of the specific tool names this server actually needs.",
                    fix_time_estimate="10 min", location=rel, confidence="high",
                ))

    # Signal 2: a config that explicitly conditions auto-approval on one of
    # the tool-annotation hint names -- covers agent harnesses other than
    # Claude Code that support this pattern natively.
    seen_files = set()
    for path in _agent_config_candidates(manifest, root):
        content = _read_capped(path)
        if content is None:
            continue
        m = ANNOTATION_TRUST_PATTERN.search(content)
        if not m:
            continue
        rel = os.path.relpath(path, root) if path.startswith(root) else path
        if rel in seen_files:
            continue
        seen_files.add(rel)
        findings.append(Finding(
            check_id="agent.trusts_mcp_tool_annotations",
            category=CATEGORY, severity=Severity.MEDIUM,
            title=f"{os.path.basename(path)} appears to auto-approve MCP tools based on a server-declared annotation",
            evidence=Evidence(file=rel, snippet=m.group(0)[:160]),
            fix="Tool annotations (readOnlyHint, destructiveHint, idempotentHint) are declared by the MCP server itself and are not verified by the client -- a malicious or buggy server can mark a destructive tool as read-only. Don't gate auto-approval on them; require explicit per-tool review instead.",
            fix_time_estimate="15 min", location=rel, confidence="medium",
        ))

    return findings


def run(manifest, root, context=None) -> list:
    findings = []
    findings += _check_broad_bash_allowlist(manifest, root)
    findings += _check_unpinned_mcp(manifest, root)
    findings += _check_unattended_separation(manifest, root)
    findings += _check_prompt_injection_reachability(manifest, root)
    findings += _check_exfiltration_triad(manifest, root)
    findings += _check_trusts_mcp_tool_annotations(manifest, root)
    return findings
