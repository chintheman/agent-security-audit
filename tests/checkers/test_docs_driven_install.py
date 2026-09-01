import json
import os
import tempfile
import unittest

from asa import manifest as manifest_mod
from asa.checkers import docs_driven_install as checker


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


class TestDocsDrivenInstall(unittest.TestCase):
    def test_flags_unpinned_pip_with_web_tool_no_approval(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), json.dumps({
                "permissions": {"allow": ["Bash(pip install *)", "WebFetch"]}
            }))
            self.assertEqual(len(hits(root)), 1)

    def test_flags_bare_npx(self):
        # npx resolves remote code at run time; a bare npx grant with no
        # @version is the exact clerk.com shape.
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), json.dumps({
                "permissions": {"allow": ["Bash(npx -y *)", "WebFetch"]}
            }))
            self.assertEqual(len(hits(root)), 1)

    def test_pinned_versions_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), json.dumps({
                "permissions": {"allow": ["Bash(pip install pkg==1.2.3)", "Bash(npx pkg@2.1.0)", "WebFetch"]}
            }))
            self.assertEqual(hits(root), [])

    def test_mutable_latest_tag_IS_flagged(self):
        # @latest re-resolves on every run -- it is the attack shape,
        # NOT a pin.
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), json.dumps({
                "permissions": {"allow": ["Bash(npx evil@latest)", "WebFetch"]}
            }))
            self.assertEqual(len(hits(root)), 1)

    def test_no_web_tool_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), json.dumps({
                "permissions": {"allow": ["Bash(pip install *)"]}
            }))
            self.assertEqual(hits(root), [])

    def test_require_confirmation_true_suppresses(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), json.dumps({
                "permissions": {"allow": ["Bash(pip install *)", "WebFetch"],
                                "requireConfirmation": True}
            }))
            self.assertEqual(hits(root), [])

    def test_require_confirmation_list_suppresses(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), json.dumps({
                "permissions": {"allow": ["Bash(pip install *)", "WebFetch"],
                                "requireConfirmation": ["Bash(pip install *)"]}
            }))
            self.assertEqual(hits(root), [])

    def test_require_confirmation_false_DOES_NOT_suppress(self):
        # A config that explicitly DISABLES confirmation has no gate.
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), json.dumps({
                "permissions": {"allow": ["Bash(pip install *)", "WebFetch"],
                                "requireConfirmation": False}
            }))
            self.assertEqual(len(hits(root)), 1)

    def test_npm_i_and_yarn_add_flagged(self):
        # Short forms are the most common unpinned installs.
        for cmd in ("Bash(npm i left-pad)", "Bash(yarn add left-pad)", "Bash(pnpm add left-pad)", "Bash(uv add left-pad)"):
            with self.subTest(cmd=cmd):
                with tempfile.TemporaryDirectory() as root:
                    write(os.path.join(root, ".claude", "settings.json"), json.dumps({
                        "permissions": {"allow": [cmd, "WebFetch"]}
                    }))
                    self.assertEqual(len(hits(root)), 1, cmd)

    def test_hermes_profile_approvals_off_flags(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".hermes", "profiles", "trading", "config.yaml"),
                  "approvals:\n  mode: off\ntoolsets:\n  - web\n  - terminal\n")
            self.assertEqual(len(hits(root)), 1)

    def test_hermes_profile_approvals_smart_suppresses(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".hermes", "profiles", "trading", "config.yaml"),
                  "approvals:\n  mode: smart\ntoolsets:\n  - web\n  - terminal\n")
            self.assertEqual(hits(root), [])

    def test_hermes_profile_no_approvals_key_defaults_gated(self):
        # Normal profile shape: toolsets only, global config holds the
        # approvals gate. Must NOT flag.
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".hermes", "profiles", "trading", "config.yaml"),
                  "name: researcher\ntoolsets:\n  - web\n  - terminal\n")
            self.assertEqual(hits(root), [])

    def test_hermes_disabled_toolsets_not_flagged(self):
        # `disabled_toolsets:` removing terminal is not a grant.
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".hermes", "profiles", "trading", "config.yaml"),
                  "approvals:\n  mode: off\ndisabled_toolsets:\n  - terminal\n  - web\n")
            self.assertEqual(hits(root), [])

    def test_hermes_webhook_toolset_not_flagged(self):
        # `toolsets: [webhook]` is not a web-content channel.
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".hermes", "profiles", "trading", "config.yaml"),
                  "approvals:\n  mode: off\ntoolsets:\n  - webhook\n  - terminal\n")
            self.assertEqual(hits(root), [])

    def test_single_line_json_does_not_mask_bare_npx(self):
        # A pin on one grant must not suppress a bare npx on the same
        # physical line (minified JSON).
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"),
                  '{"permissions":{"allow":["Bash(npx foo)","Bash(pip install bar==1.0)","WebFetch"]}}')
            self.assertEqual(len(hits(root)), 1)

    def test_mcp_web_server_flags(self):
        # A web-fetch MCP server counts as the untrusted channel.
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".mcp.json"), json.dumps({
                "mcpServers": {"web": {"command": "npx", "args": ["-y", "web-fetch-mcp"]}}
            }))
            self.assertEqual(len(hits(root)), 1)

    def test_mcp_pinned_server_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".mcp.json"), json.dumps({
                "mcpServers": {"web": {"command": "npx", "args": ["-y", "web-fetch-mcp@1.0.0"]}}
            }))
            self.assertEqual(hits(root), [])

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
