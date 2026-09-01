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

Approval-gate defaults matter, and they differ per stack:

  * Hermes ships `approvals.mode: smart`, and the approvals key lives in
    the component's GLOBAL config while toolsets live in each profile.
    Gate state is therefore hoisted to the component (see run()'s pass
    2), and a profile that declares no approvals at all defaults to
    GATED (no finding), not ungated.
  * A Claude Code `permissions.allow` entry is itself the statement
    "run this without prompting" -- an explicit grant, so it is reported
    even with no `requireConfirmation` key present. `requireConfirmation:
    false` is the same thing said twice, and only that affirmative
    off-switch earns MEDIUM; everything else is LOW.
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

# Claude/MCP approval gate in NON-JSON (YAML, or JSON too malformed to
# parse) config text. The value matters, not just the key: a bare
# `requireConfirmation` mention must never suppress a finding.
REQUIRE_CONFIRMATION_ON = re.compile(
    r'(?i)"?require[_]?[Cc]onfirmation"?\s*[:=]\s*(?:true|"?(?:always|ask)"?)'
)
REQUIRE_CONFIRMATION_OFF = re.compile(
    r'(?i)"?require[_]?[Cc]onfirmation"?\s*[:=]\s*(?:false|"?never"?)'
)

# Gate states. ABSENT is not the same as OFF: it only downgrades
# severity, whereas ON suppresses the finding outright.
GATE_ON = "on"
GATE_OFF = "off"
GATE_ABSENT = "absent"

# Claude-style untrusted-input tools.
UNTRUSTED_INPUT_KEYWORDS = re.compile(
    r"(?i)\b(web[_-]?fetch|read[_-]?webpage|browse|web[_-]?search|gmail|email|"
    r"read[_-]?url|http[_-]?request|fetch[_-]?url|rss|news[_-]?feed|"
    r"web[_-]?extract|web[_-]?scrape)\b"
)


def activates(manifest) -> bool:
    return manifest.has_kind("claude_code_config") or manifest.has_kind("mcp_config") or manifest.has_kind("hermes_profile")


def _iter_text_configs(manifest, root):
    """Yield (kind, comp_dir, path, content) for every agent config file
    the manifest knows.

    `comp_dir` is the COMPONENT root, not the file's directory: pass 2
    needs it to hoist approval-gate state across every file of a Hermes
    component, because approvals are declared in the global config while
    toolsets are declared per profile.
    """
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
                yield kind, comp_dir, path, content


_MISSING = object()


def _json_gate_state(data: dict) -> str:
    """Claude/MCP JSON gate, read by VALUE and not by key presence.

    requireConfirmation truthy (true / non-empty list / "always" / "ask")
    or a non-empty permissions.ask is a real gate -> GATE_ON.
    An explicit `false` / `never` / empty list is the gate affirmatively
    switched off -> GATE_OFF. No such key at all -> GATE_ABSENT.
    """
    perm = data.get("permissions")
    if not isinstance(perm, dict):
        perm = {}
    rc = data.get("requireConfirmation", perm.get("requireConfirmation", _MISSING))
    if rc is True:
        return GATE_ON
    if isinstance(rc, list) and rc:
        return GATE_ON
    if isinstance(rc, str) and rc.lower() in ("always", "ask", "true"):
        return GATE_ON
    ask = perm.get("ask")
    if isinstance(ask, list) and ask:
        return GATE_ON
    return GATE_ABSENT if rc is _MISSING else GATE_OFF


def _text_gate_state(content: str) -> str:
    """Same question as _json_gate_state for config text we could not parse."""
    if REQUIRE_CONFIRMATION_ON.search(content):
        return GATE_ON
    if REQUIRE_CONFIRMATION_OFF.search(content):
        return GATE_OFF
    return GATE_ABSENT


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
            for name, spec in servers.items():
                if isinstance(spec, dict):
                    if UNTRUSTED_INPUT_KEYWORDS.search(_server_invocation(name, spec)):
                        return True
    return False


def _server_invocation(name: str, spec: dict) -> str:
    """`name command arg arg` for one mcpServers entry."""
    command = str(spec.get("command", ""))
    args = [str(a) for a in spec.get("args", []) if isinstance(a, str)]
    return " ".join([str(name), command] + args).strip()


def _hermes_toolsets(content: str) -> tuple:
    """Key-aware scan of a Hermes profile config. Returns (has_terminal,
    has_web).

    Only list items under an ACTIVE `toolsets:` / `enabled_toolsets:`
    block count. `disabled_toolsets:` is explicitly ignored, and list
    items under any other key (- webhook, - email) are ignored. A
    trailing `# no web access here` comment can never supply a toolset,
    because only the bracket body / list items are read.
    """
    has_terminal = False
    has_web = False
    active_toolsets_key = False
    for line in content.splitlines():
        stripped = line.strip()
        if re.match(r"(?i)^toolsets?\s*:", stripped):
            inline = INLINE_TOOLSETS.search(line)
            if inline:
                inner = inline.group(1)
                if re.search(r"(?i)\bterminal\b", inner):
                    has_terminal = True
                if re.search(r"(?i)\bweb\b", inner):
                    has_web = True
                # An inline [a, b] list is complete on this line -- the
                # block does not continue onto following list items.
                active_toolsets_key = False
            else:
                active_toolsets_key = True
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
            elif re.search(r"(?i)^web\b", item):
                has_web = True
        elif not stripped.startswith("-") and stripped and not stripped.startswith("#"):
            # A new top-level or nested key ends the toolsets block.
            if re.match(r"(?i)^[a-z0-9_]+:", stripped):
                active_toolsets_key = False
    return has_terminal, has_web


def _json_install_grants(data: dict) -> list:
    """Explicit allow-list entries OR MCP server invocations that look
    like install grants (command npx/pip/npm with their args).

    Each grant is returned as its OWN string: the pin check runs per
    permission, never per physical line, so a pinned entry sitting next
    to an unpinned one in minified JSON cannot mask it.
    """
    out = []
    perm = data.get("permissions")
    allow_lists = [perm.get("allow") if isinstance(perm, dict) else None, data.get("allow")]
    for allow in allow_lists:
        if isinstance(allow, list):
            out.extend(str(a) for a in allow if INSTALL_GRANT.search(str(a)))
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            command = str(spec.get("command", ""))
            args = [str(a) for a in spec.get("args", []) if isinstance(a, str)]
            joined = " ".join([command] + args).strip()
            if INSTALL_GRANT.search(joined):
                out.append(joined)
    return out


def _severity(unpinned_grants: list, gate: str) -> Severity:
    """MEDIUM is reserved for an explicit install grant PLUS a gate that
    is affirmatively switched off. A bare `npx` grant is on essentially
    every stock MCP config, so it stays LOW and never drowns the signal.
    """
    npx_only = all("npx" in g.lower() for g in unpinned_grants)
    if gate == GATE_OFF and not npx_only:
        return Severity.MEDIUM
    return Severity.LOW


def _hermes_gate_off(content: str, inherited_off: bool) -> bool:
    """Is the approval gate off for THIS Hermes file?

    A profile's own declaration wins; a silent profile inherits the
    component's global declaration; and a component that never mentions
    approvals is GATED, because Hermes ships `approvals.mode: smart`.
    """
    if HERMES_NO_APPROVAL.search(content):
        return True
    if HERMES_APPROVAL_GATED.search(content):
        return False
    return inherited_off


def run(manifest, root, context=None) -> list:
    findings = []
    hermes_components = {}

    # ---- Pass 1: Claude / MCP shapes ----
    for kind, comp_dir, path, content in _iter_text_configs(manifest, root):
        if kind == "hermes_profile":
            hermes_components.setdefault(comp_dir, []).append((path, content))
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
            gate = _json_gate_state(data)
        else:
            # Not JSON we can parse -- fall back to line-splitting, which
            # is only safe for YAML (one grant per line by construction).
            grants = [line for line in content.splitlines() if INSTALL_GRANT.search(line)]
            gate = _text_gate_state(content)

        if not grants or gate == GATE_ON:
            continue
        unpinned = [g for g in grants if _grant_is_unpinned(g)]
        if not unpinned:
            continue
        findings.append(_finding(rel, _severity(unpinned, gate)))

    # ---- Pass 2: Hermes profiles, with gate state hoisted to the
    # component. Approvals live in the component's global config while
    # toolsets live in each profile, so a per-file read of the gate
    # false-flags every ordinary profile. ----
    for comp_dir, files in hermes_components.items():
        component_off = any(HERMES_NO_APPROVAL.search(c) for _, c in files)
        component_gated = any(HERMES_APPROVAL_GATED.search(c) for _, c in files)
        # What a profile that says nothing about approvals inherits. If
        # the component both gates somewhere and disables somewhere, the
        # silent profiles keep the gate; only the file that turned it off
        # is treated as ungated (see _hermes_gate_off).
        inherited_off = component_off and not component_gated

        for path, content in files:
            if not _hermes_gate_off(content, inherited_off):
                continue
            has_terminal, has_web = _hermes_toolsets(content)
            if not has_terminal:
                continue
            if not (has_web or UNTRUSTED_INPUT_KEYWORDS.search(content)):
                continue
            rel = os.path.relpath(path, root) if path.startswith(root) else path
            # The gate is affirmatively off and `terminal` is a real
            # install capability, not a bare npx line -> MEDIUM.
            findings.append(_finding(rel, Severity.MEDIUM))
    return findings


def _finding(rel: str, severity: Severity) -> Finding:
    if severity == Severity.LOW:
        title = (f"{os.path.basename(rel)} grants an unpinned install/`npx` command (which fetches and runs "
                 f"remote code) while also reading untrusted web content")
    else:
        title = (f"{os.path.basename(rel)} grants unpinned package installs while also reading untrusted "
                 f"web content, with the approval gate explicitly off")
    return Finding(
        check_id="agent.docs_driven_install_unpinned",
        category=CATEGORY, severity=severity,
        title=title,
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
