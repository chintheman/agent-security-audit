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
"""

from __future__ import annotations

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
    r"(?i)\b(?:pip|pip3|uv)\s+install\b"
    r"|\b(?:npm|pnpm|yarn)\s+(?:install|i|add)\b"
    r"|\bnpx\b"
)

# A grant that names at least one concrete version pin is NOT unpinned.
VERSION_PIN = re.compile(r"(?i)@\d+(?:\.\d+){0,2}|==\s*\d|~\=\s*\d|@latest")
GLOBAL_FLAG = re.compile(r"(?i)(?:-g|--global|global\s+add)")

# Hermes profiles express capability as toolsets, not permission strings:
# the `terminal` toolset is what can run `pip install` / `npx`; `web`
# is the untrusted-content channel. Both list-item (`  - terminal`)
# and inline (`toolsets: [web, terminal]`) shapes are covered.
HERMES_TERMINAL_TOOLSET = re.compile(r"(?im)(?:^[ \t]*-[ \t]*terminal\b|toolsets?\s*[:=][^\n]*terminal)")
HERMES_WEB_TOOLSET = re.compile(r"(?im)(?:^[ \t]*-[ \t]*web\b|toolsets?\s*[:=][^\n]*web)")
HERMES_NO_APPROVAL = re.compile(
    r"(?im)approvals?\s*:\s*(?:off|yolo|none)\s*$"
    r"|approvals?\s*:\s*mode\s*:\s*(?:off|yolo|none)"
)
# Any other approvals mode (manual, smart) IS a gate for Hermes.
HERMES_APPROVAL_GATED = re.compile(
    r"(?im)approvals?\s*:\s*(?:manual|smart|ask|require)\b"
    r"|approvals?\s*:\s*mode\s*:\s*(?:manual|smart|ask|require)\b"
)

UNTRUSTED_INPUT_KEYWORDS = re.compile(
    r"(?i)\b(web[_-]?fetch|read[_-]?webpage|browse|web[_-]?search|gmail|email|"
    r"read[_-]?url|http[_-]?request|fetch[_-]?url|rss|news[_-]?feed|"
    r"web[_-]?extract|web[_-]?scrape)\b"
)
APPROVAL_MARKERS = re.compile(
    r"(?i)\b(requireConfirmation|require_confirmation|approval|confirm|ask[_-]?before)\b"
)
HERMES_NO_APPROVAL = re.compile(r"(?i)^\s*approvals?\s*:\s*(off|yolo|none)\s*$", re.MULTILINE)


def activates(manifest) -> bool:
    return manifest.has_kind("claude_code_config") or manifest.has_kind("mcp_config") or manifest.has_kind("hermes_profile")


def _iter_text_configs(manifest, root):
    """Yield (path, content) for every agent config file the manifest knows."""
    seen = set()
    for kind in ("claude_code_config", "mcp_config", "hermes_profile"):
        for comp in manifest.components_of(kind):
            comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
            files = list(comp.signature_files)
            # hermes_profile components are directories; walk them for
            # config-shaped files so approvals.mode is visible.
            if kind == "hermes_profile" and os.path.isdir(comp_dir):
                for dirpath, _, filenames in os.walk(comp_dir):
                    for fname in filenames:
                        if fname.endswith((".yaml", ".yml", ".json")):
                            files.append(os.path.relpath(os.path.join(dirpath, fname), comp_dir))
            for fname in files:
                path = os.path.join(comp_dir, fname) if os.path.isabs(fname) else os.path.join(comp_dir, fname)
                path = os.path.normpath(path)
                if path in seen:
                    continue
                seen.add(path)
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue
                yield path, content


def run(manifest, root, context=None) -> list:
    findings = []
    for path, content in _iter_text_configs(manifest, root):
        rel = os.path.relpath(path, root) if path.startswith(root) else path

        # Install capability: literal pip/npm/npx permission strings
        # (Claude/MCP shape) OR the Hermes `terminal` toolset.
        has_install = bool(INSTALL_GRANT.search(content)) or bool(HERMES_TERMINAL_TOOLSET.search(content))
        if not has_install:
            continue

        # Untrusted-content channel present? Without a web/read-input
        # tool the docs-driven chain can't start.
        has_web = bool(UNTRUSTED_INPUT_KEYWORDS.search(content)) or bool(HERMES_WEB_TOOLSET.search(content))
        if not has_web:
            continue

        # Approval gate present? Hermes profiles: approvals.mode off/yolo
        # means no gate; manual/smart IS a gate. Claude-style: any
        # approval marker means a gate.
        hermes_off = HERMES_NO_APPROVAL.search(content)
        if not hermes_off and (APPROVAL_MARKERS.search(content) or HERMES_APPROVAL_GATED.search(content)):
            continue

        # Hermes profiles: terminal toolset is by definition unpinned
        # (any package can be fetched); flag directly.
        if HERMES_TERMINAL_TOOLSET.search(content):
            findings.append(_finding(rel))
            continue

        # Claude/MCP shape: did the install grants come with version
        # pins? Walk each install-looking line; flag the file if ANY
        # install grant is unpinned. npx without a pin always counts
        # (remote exec).
        unpinned_found = False
        for line in content.splitlines():
            if not INSTALL_GRANT.search(line):
                continue
            if "npx" in line.lower() and not VERSION_PIN.search(line):
                unpinned_found = True
                break
            if VERSION_PIN.search(line):
                continue
            if GLOBAL_FLAG.search(line) or "install" in line.lower():
                unpinned_found = True
                break
        if unpinned_found:
            findings.append(_finding(rel))
    return findings


def _finding(rel: str) -> Finding:
    return Finding(
        check_id="agent.docs_driven_install_unpinned",
        category=CATEGORY, severity=Severity.MEDIUM,
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
