"""Docs-driven package-install checks (the llms.txt supply-chain vector).

Aug 2026: researchers showed that agent-readable docs files (llms.txt /
llms-full.txt) at corporate sites told agents to `pip install <name>` /
`npm install <name>` / `npx <name>` where the name had never been
registered. Registering the name yields code execution inside any agent
that follows the docs. One live case (clerk.com) already hosted malware.

The config-level precondition is three things in one agent config:

  1. an install-command grant with no version pin  (pip/npm/npx/pnpm/
     yarn/uv, or a bare `npx` -- which fetches remote code at run time)
  2. a channel for untrusted web content (web fetch, read webpage, web
     search -- the "docs" side of the attack)
  3. no approval gate between them

  1. docs_driven_install_unpinned -- heuristic; flags the combination,
     not the individual entries. Static config shape only -- the actual
     registry-ownership check (does the package exist / who owns it) is
     inherently dynamic and belongs in the fix workflow, not in a scan.

Approval-gate defaults matter: Hermes ships `approvals.mode: smart` and
Claude Code ships confirmation prompts. Absence of an approvals
declaration therefore defaults to GATED (no finding), not ungated.
"""

from __future__ import annotations

import json
import os
import re

from asa.finding import Category, Evidence, Finding, Severity

CATEGORY = Category.AGENT
CHECK_IDS = ["agent.docs_driven_install_unpinned"]

# Install-command grant shapes inside permission strings, e.g. Claude
# Code's "Bash(pip install *)" / "Bash(npx -y foo)" entries. npx is
# special: it resolves and executes remote code by design, so ANY bare
# npx grant (no @version) is effectively unpinned remote execution.
INSTALL_GRANT = re.compile(
    r"(?i)\b(?:pip|pip3)\s+install\b"
    r"|\buv\s+(?:add|pip\s+install|tool\s+install)\b"
    r"|\b(?:npm|pnpm)\s+(?:install|i|add)\b"
    r"|\byarn\s+(?:install|add)\b"
    r"|\bnpx\b"
)

# A grant that names at least one concrete version pin is NOT unpinned.
# `@latest` / `@next` / `@beta` / `@canary` are MUTABLE tags -- they
# re-resolve on every run and are exactly the attack shape, so they are
# handled separately (MUTABLE_TAG) and force unpinned.
VERSION_PIN = re.compile(r"(?i)@\d+(?:\.\d+){0,2}|==\s*\d")
MUTABLE_TAG = re.compile(r"(?i)@(?:latest|next|beta|canary|\*)")

# Hermes profiles express capability as toolsets, not permission strings:
# the `terminal` toolset is what can run `pip install` / `npx`; `web`
# is the untrusted-content channel. Detection is key-aware line-scanning
# (see _hermes_toolsets) so `disabled_toolsets:` never counts as a grant.
INLINE_TOOLSETS = re.compile(r"(?i)^[ \t]*toolsets?\s*:\s*\[([^\]]*)\]")

# Hermes approvals gates. Absence of an approvals declaration is GATED.
HERMES_NO_APPROVAL = re.compile(
    r"(?im)^\s*approvals?\s*:\s*(?:off|yolo|none)\s*$"
    r"|^\s*approvals?\s*:\s*[^\n]*\n\s*mode\s*:\s*(?:off|yolo|none)\s*$"
)
# Any other approvals mode (manual, smart) IS a gate for Hermes.
HERMES_APPROVAL_GATED = re.compile(
    r"(?im)^\s*approvals?\s*:\s*(?:manual|smart|ask|require)\b"
    r"|^\s*approvals?\s*:\s*[^\n]*\n\s*mode\s*:\s*(?:manual|smart|ask|require)\b"
)

# Claude-style untrusted-input tools.
UNTRUSTED_INPUT_KEYWORDS = re.compile(
    r"(?i)\b(web[_-]?fetch|read[_-]?webpage|browse|web[_-]?search|gmail|email|"
    r"read[_-]?url|http[_-]?request|fetch[_-]?url|rss|news[_-]?feed|"
    r"web[_-]?extract|web[_-]?scrape)\b"
)


def activates(manifest) -> bool:
    return manifest.has_kind("claude_code_config") or manifest.has_kind("mcp_config") or manifest.has_kind("hermes_profile")


def _iter_text_configs(manifest, root):
    """Yield (kind, path, content) for every agent config file the manifest knows."""
    seen = set()
    for kind in ("claude_code_config", "mcp_config", "hermes_profile"):
        for comp in manifest.components_of(kind):
            comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
            files = list(comp.signature_files)
            if kind == "hermes_profile" and os.path.isdir(comp_dir):
                for dirpath, _, filenames in os.walk(comp_dir):
                    for fname in filenames:
                        if fname.endswith((".yaml", ".yml", ".json", ".md")):
                            files.append(os.path.relpath(os.path.join(dirpath, fname), comp_dir))
            for fname in files:
                path = os.path.normpath(os.path.join(comp_dir, fname))
                if path in seen:
                    continue
                seen.add(path)
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue
                yield kind, path, content


def _json_gated(data: dict) -> bool:
    """Claude/MCP JSON gate: requireConfirmation truthy (true or non-empty
    list) OR permissions.ask non-empty means an approval gate exists.
    `requireConfirmation: false` / empty list / absent = NO gate."""
    perm = data.get("permissions")
    if not isinstance(perm, dict):
        perm = {}
    rc = data.get("requireConfirmation", perm.get("requireConfirmation"))
    if rc is True:
        return True
    if isinstance(rc, list) and rc:
        return True
    if isinstance(rc, str) and rc.lower() in ("always", "ask", "true"):
        return True
    ask = perm.get("ask")
    if isinstance(ask, list) and ask:
        return True
    return False


def _grant_is_unpinned(text: str) -> bool:
    """True when an install grant has no concrete version pin."""
    if MUTABLE_TAG.search(text):
        return True
    if VERSION_PIN.search(text):
        return False
    return True


def _has_web_channel(content: str, data: dict | None) -> bool:
    if UNTRUSTED_INPUT_KEYWORDS.search(content):
        return True
    inline = INLINE_TOOLSETS.search(content)
    if inline and re.search(r"(?i)\bweb\b", inline.group(1)):
        return True
    if isinstance(data, dict):
        # mcpServers: a web-fetch server counts as the untrusted channel
        servers = data.get("mcpServers")
        if isinstance(servers, dict):
            for spec in servers.values():
                if isinstance(spec, dict):
                    joined = " ".join(str(spec.get("command", ""))) + " " + " ".join(str(a) for a in spec.get("args", []) if isinstance(a, str))
                    if UNTRUSTED_INPUT_KEYWORDS.search(joined):
                        return True
    return False


def _hermes_toolsets(content: str) -> tuple:
    """Key-aware scan of a Hermes profile config. Returns (has_terminal,
    has_web, has_install_capability).

    Only list items under an ACTIVE `toolsets:` / `enabled_toolsets:`
    block count. `disabled_toolsets:` is explicitly ignored, and list
    items under any other key (- webhook, - email) are ignored.
    """
    has_terminal = False
    has_web = False
    has_install_capability = False
    active_toolsets_key = False
    for line in content.splitlines():
        stripped = line.strip()
        if re.match(r"(?i)^toolsets?\s*:", stripped):
            active_toolsets_key = True
            inline = INLINE_TOOLSETS.search(line)
            if inline:
                inner = inline.group(1)
                if re.search(r"(?i)\bterminal\b", inner):
                    has_terminal = True
                    has_install_capability = True
                if re.search(r"(?i)\bweb\b", inner):
                    has_web = True
            continue
        if re.match(r"(?i)^(?:disabled|enabled_)?toolsets?\s*:", stripped):
            # A variant key (disabled_toolsets: / enabled_toolsets:).
            # enabled_ counts as a grant; disabled_ explicitly does NOT.
            if re.match(r"(?i)^enabled_toolsets?\s*:", stripped):
                active_toolsets_key = True
            else:
                active_toolsets_key = False
            continue
        if active_toolsets_key and stripped.startswith("-"):
            item = stripped[1:].strip()
            if re.search(r"(?i)^terminal\b", item):
                has_terminal = True
                has_install_capability = True
            elif re.search(r"(?i)^web\b", item):
                has_web = True
        elif not stripped.startswith("-") and stripped and not stripped.startswith("#"):
            # A new top-level or nested key ends the toolsets block.
            if re.match(r"(?i)^[a-z0-9_]+:", stripped):
                active_toolsets_key = False
    return has_terminal, has_web, has_install_capability


def _json_install_grants(data: dict) -> list:
    """Explicit allow-list entries OR MCP server invocations that look
    like install grants (command npx/pip/npm with their args)."""
    out = []
    perm = data.get("permissions")
    if isinstance(perm, dict):
        allow = perm.get("allow")
        if isinstance(allow, list):
            out.extend(str(a) for a in allow if INSTALL_GRANT.search(str(a)))
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            command = str(spec.get("command", ""))
            args = [str(a) for a in spec.get("args", []) if isinstance(a, str)]
            joined = " ".join([command] + args)
            if INSTALL_GRANT.search(joined):
                out.append(f"{command} {' '.join(args)}".strip())
    return out


def run(manifest, root, context=None) -> list:
    findings = []

    # ---- Pass 1: Claude / MCP (JSON) shapes ----
    for kind, path, content in _iter_text_configs(manifest, root):
        if kind == "hermes_profile":
            continue
        rel = os.path.relpath(path, root) if path.startswith(root) else path
        if not INSTALL_GRANT.search(content):
            continue

        try:
            data = json.loads(content)
        except ValueError:
            data = None

        if not _has_web_channel(content, data):
            continue

        if isinstance(data, dict):
            grants = _json_install_grants(data)
            if not grants:
                continue
            if _json_gated(data):
                continue
            unpinned = any(_grant_is_unpinned(g) for g in grants)
            if not unpinned:
                continue
            npx_only = all("npx" in g.lower() for g in grants)
            findings.append(_finding(rel, Severity.LOW if npx_only else Severity.MEDIUM))
        else:
            # YAML/text fallback: per-line pin check.
            grants = [line for line in content.splitlines() if INSTALL_GRANT.search(line)]
            if not grants:
                continue
            unpinned = any(_grant_is_unpinned(g) for g in grants)
            if not unpinned:
                continue
            npx_only = all("npx" in g.lower() for g in grants)
            findings.append(_finding(rel, Severity.LOW if npx_only else Severity.MEDIUM))

    # ---- Pass 2: Hermes profiles with component-level gate state ----
    profile_files = {}
    for kind, path, content in _iter_text_configs(manifest, root):
        if kind != "hermes_profile":
            continue
        rel = os.path.relpath(path, root) if path.startswith(root) else path
        profile_files.setdefault(rel, []).append(content)

    for rel, contents in profile_files.items():
        joined = "\n".join(contents)
        off = bool(HERMES_NO_APPROVAL.search(joined))
        gated = bool(HERMES_APPROVAL_GATED.search(joined))
        # Default when nothing declares approvals: GATED (Hermes ships smart).
        if not off and (gated or not re.search(r"(?im)^\s*approvals?\s*:", joined)):
            continue
        has_terminal, has_web, has_install = _hermes_toolsets(joined)
        if not (has_install or has_terminal):
            continue
        if not has_web:
            continue
        findings.append(_finding(rel, Severity.MEDIUM))
    return findings


def _finding(rel: str, severity: Severity) -> Finding:
    return Finding(
        check_id="agent.docs_driven_install_unpinned",
        category=CATEGORY, severity=severity,
        title=f"{os.path.basename(rel)} grants unpinned package installs while also reading untrusted web content, with no approval gate",
        evidence=Evidence(file=rel),
        fix=("Pin every install to an exact version (pip pkg==x.y.z, npm pkg@x.y.z, npx pkg@x.y.z) and add an approval "
             "gate before install commands can run. Before installing anything a vendor doc recommends, verify the "
             "registry name is actually owned by the vendor (pip index versions <pkg> / npm view <pkg> and check the "
             "publisher) -- an unregistered name can be claimed by anyone, which is the llms.txt supply-chain vector."),
        fix_time_estimate="15 min", location=rel, confidence="low",
        references=[
            "https://arstechnica.com/security/2026/08/claude-codex-and-hermes-installed-unowned-code-inside-corporate-networks/",
            "https://medium.com/@alonhertz1/data-became-code-we-ran-code-inside-fortune-500s-using-files-they-published-for-ai-agents-0cd67ffbbffc",
        ],
    )
