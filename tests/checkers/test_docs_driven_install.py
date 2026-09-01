import json
import os
import tempfile
import unittest

from asa import manifest as manifest_mod
from asa.checkers import docs_driven_install as checker
from asa.finding import Severity


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def run_checker(root, context=None):
    m = manifest_mod.build(root)
    return checker.run(m, root, context)


def hits(root, context=None):
    return [f for f in run_checker(root, context) if f.check_id == "agent.docs_driven_install_unpinned"]


class TestActivation(unittest.TestCase):
    def test_does_not_activate_without_agent_config(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), "{}")
            m = manifest_mod.build(root)
            self.assertFalse(checker.activates(m))

    def test_activates_with_claude_settings(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), "{}")
            m = manifest_mod.build(root)
            self.assertTrue(checker.activates(m))


# Every case below is a behaviour an independent review of this checker
# either found broken or explicitly pinned down. `None` means "must not
# flag"; a Severity means "must flag exactly once, at this severity".
#
# Severity rule under test: MEDIUM is reserved for an install grant plus
# an approval gate that is affirmatively OFF. Everything else -- an
# absent gate, or an npx-only grant (which is on nearly every stock MCP
# config) -- is LOW so it cannot drown the signal.
CASES = [
    # ---- Hermes approvals gate: the nested shape is how Hermes writes it ----
    (
        "hermes nested approvals off, with the word approval elsewhere in the text",
        {".hermes/profiles/trading/config.yaml":
            "name: trading\n"
            "approvals:\n  mode: off\n"
            "notes: approval required by policy before large trades\n"
            "toolsets:\n  - web\n  - terminal\n"},
        Severity.MEDIUM,
    ),
    (
        "hermes nested approvals off with web+terminal toolsets",
        {".hermes/profiles/trading/config.yaml":
            "approvals:\n  mode: off\ntoolsets:\n  - web\n  - terminal\n"},
        Severity.MEDIUM,
    ),
    (
        "hermes approvals smart with web+terminal toolsets",
        {".hermes/profiles/trading/config.yaml":
            "approvals:\n  mode: smart\ntoolsets:\n  - web\n  - terminal\n"},
        None,
    ),
    (
        "plain hermes profile, no approvals key at all, defaults to GATED",
        {".hermes/profiles/researcher/config.yaml":
            "name: researcher\ntoolsets: [web, terminal]\n"},
        None,
    ),
    (
        "gate hoisted to the component: approvals off in the global config, "
        "toolsets in the profile",
        {".hermes/config.yaml": "approvals:\n  mode: off\n",
         ".hermes/profiles/researcher/config.yaml":
            "name: researcher\ntoolsets:\n  - web\n  - terminal\n"},
        Severity.MEDIUM,
    ),
    (
        "component gates globally, one profile turns it off: only that profile flags",
        {".hermes/config.yaml": "approvals:\n  mode: smart\n",
         ".hermes/profiles/safe/config.yaml": "name: safe\ntoolsets:\n  - web\n  - terminal\n",
         ".hermes/profiles/yolo/config.yaml":
            "name: yolo\napprovals:\n  mode: off\ntoolsets:\n  - web\n  - terminal\n"},
        Severity.MEDIUM,
    ),
    # ---- Hermes toolset parsing: negations, comments, prefixes ----
    (
        "disabled_toolsets is not a grant",
        {".hermes/profiles/trading/config.yaml":
            "approvals:\n  mode: off\ndisabled_toolsets:\n  - terminal\n  - web\n"},
        None,
    ),
    (
        "a trailing comment cannot supply the web channel",
        {".hermes/profiles/trading/config.yaml":
            "approvals:\n  mode: off\ntoolsets: [terminal]  # no web access here\n"},
        None,
    ),
    (
        "webhook is not web",
        {".hermes/profiles/trading/config.yaml":
            "approvals:\n  mode: off\ntoolsets: [webhook, terminal]\n"},
        None,
    ),
    # ---- Version pins vs mutable tags ----
    (
        "@latest is a mutable tag, not a pin",
        {".claude/settings.json": json.dumps({
            "permissions": {"allow": ["Bash(npx evil@latest)"]}, "tools": ["web_fetch"]})},
        Severity.LOW,
    ),
    (
        "exact pins are not flagged",
        {".claude/settings.json": json.dumps({
            "permissions": {"allow": ["Bash(pip install pkg==1.2.3)",
                                      "Bash(npm install pkg@1.2.3)", "WebFetch"]}})},
        None,
    ),
    # ---- Short-form installs: no "install" substring, no npx, no global flag ----
    (
        "npm i",
        {".claude/settings.json": json.dumps({
            "permissions": {"allow": ["Bash(npm i left-pad)", "WebFetch"]}})},
        Severity.LOW,
    ),
    (
        "yarn add",
        {".claude/settings.json": json.dumps({
            "permissions": {"allow": ["Bash(yarn add left-pad)", "WebFetch"]}})},
        Severity.LOW,
    ),
    (
        "pnpm add",
        {".claude/settings.json": json.dumps({
            "permissions": {"allow": ["Bash(pnpm add left-pad)", "WebFetch"]}})},
        Severity.LOW,
    ),
    (
        "uv add",
        {".claude/settings.json": json.dumps({
            "permissions": {"allow": ["Bash(uv add left-pad)", "WebFetch"]}})},
        Severity.LOW,
    ),
    # ---- Approval gate read by value, never by key presence ----
    (
        "requireConfirmation false is a gate that is explicitly OFF",
        {".claude/settings.json": json.dumps({
            "allow": ["Bash(npx evil)"], "tools": ["web_fetch"], "requireConfirmation": False})},
        Severity.LOW,
    ),
    (
        "requireConfirmation false on a non-npx grant earns MEDIUM",
        {".claude/settings.json": json.dumps({
            "permissions": {"allow": ["Bash(pip install *)", "WebFetch"],
                            "requireConfirmation": False}})},
        Severity.MEDIUM,
    ),
    (
        "requireConfirmation true suppresses",
        {".claude/settings.json": json.dumps({
            "permissions": {"allow": ["Bash(pip install *)", "WebFetch"],
                            "requireConfirmation": True}})},
        None,
    ),
    (
        "non-empty requireConfirmation list suppresses",
        {".claude/settings.json": json.dumps({
            "permissions": {"allow": ["Bash(pip install *)", "WebFetch"],
                            "requireConfirmation": ["Bash(pip install *)"]}})},
        None,
    ),
    # ---- Per-permission, not per physical line ----
    (
        "minified JSON: a pinned grant must not mask a bare npx on the same line",
        {".claude/settings.json":
            '{"permissions":{"allow":["Bash(npx foo)","Bash(pip install bar==1.0)","WebFetch"]}}'},
        Severity.LOW,
    ),
    # ---- Stock MCP configs stay quiet or stay LOW ----
    (
        "stock MCP filesystem server alone: no untrusted-content channel, no finding",
        {".mcp.json": json.dumps({"mcpServers": {"filesystem": {
            "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}})},
        None,
    ),
    (
        "stock MCP servers plus a web-fetch server: LOW, not MEDIUM",
        {".mcp.json": json.dumps({"mcpServers": {
            "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]},
            "fetch": {"command": "npx", "args": ["-y", "web-fetch-mcp"]}}})},
        Severity.LOW,
    ),
    (
        "pinned MCP server is not flagged",
        {".mcp.json": json.dumps({"mcpServers": {"web": {
            "command": "npx", "args": ["-y", "web-fetch-mcp@1.0.0"]}}})},
        None,
    ),
    # ---- The untrusted-content channel is required ----
    (
        "install grant with no web channel is not flagged",
        {".claude/settings.json": json.dumps({"permissions": {"allow": ["Bash(pip install *)"]}})},
        None,
    ),
    (
        "unpinned pip plus WebFetch with no gate declared",
        {".claude/settings.json": json.dumps({
            "permissions": {"allow": ["Bash(pip install *)", "WebFetch"]}})},
        Severity.LOW,
    ),
    (
        "bare npx grant plus WebFetch",
        {".claude/settings.json": json.dumps({
            "permissions": {"allow": ["Bash(npx -y *)", "WebFetch"]}})},
        Severity.LOW,
    ),
]


class TestDocsDrivenInstall(unittest.TestCase):
    def test_cases(self):
        for name, files, expected in CASES:
            with self.subTest(case=name):
                with tempfile.TemporaryDirectory() as root:
                    for rel, content in files.items():
                        write(os.path.join(root, *rel.split("/")), content)
                    found = hits(root)
                    if expected is None:
                        self.assertEqual(
                            [f.title for f in found], [], f"{name}: expected no finding")
                    else:
                        self.assertEqual(len(found), 1, f"{name}: expected exactly one finding")
                        self.assertEqual(found[0].severity, expected, name)

    def test_malformed_json_does_not_crash(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), "{not valid")
            self.assertIsInstance(run_checker(root), list)

    def test_no_permissions_key_does_not_crash(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), json.dumps({"theme": "dark"}))
            self.assertIsInstance(run_checker(root), list)


if __name__ == "__main__":
    unittest.main()
