import json
import os
import tempfile
import unittest

from asa import manifest as manifest_mod
from asa.checkers import agent_blast_radius as agent_checker


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def run_agent(root, context=None):
    m = manifest_mod.build(root)
    return agent_checker.run(m, root, context)


class TestActivation(unittest.TestCase):
    def test_does_not_activate_without_agent_config(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), "{}")
            m = manifest_mod.build(root)
            self.assertFalse(agent_checker.activates(m))

    def test_activates_with_claude_settings(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), "{}")
            m = manifest_mod.build(root)
            self.assertTrue(agent_checker.activates(m))


class TestBroadBashAllowlist(unittest.TestCase):
    def test_flags_bash_star(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), json.dumps({
                "permissions": {"allow": ["Bash(*)", "Read"]}
            }))
            findings = run_agent(root)
            hits = [f for f in findings if f.check_id == "agent.broad_bash_allowlist"]
            self.assertEqual(len(hits), 1)

    def test_scoped_bash_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), json.dumps({
                "permissions": {"allow": ["Bash(git *)", "Bash(npm test)"]}
            }))
            findings = run_agent(root)
            hits = [f for f in findings if f.check_id == "agent.broad_bash_allowlist"]
            self.assertEqual(hits, [])

    def test_no_permissions_key_does_not_crash(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), json.dumps({"theme": "dark"}))
            findings = run_agent(root)
            self.assertIsInstance(findings, list)

    def test_malformed_json_does_not_crash(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), "{not valid")
            findings = run_agent(root)
            self.assertIsInstance(findings, list)


class TestUnpinnedMcp(unittest.TestCase):
    def test_flags_bare_package_name(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".mcp.json"), json.dumps({
                "mcpServers": {"brave": {"command": "npx", "args": ["-y", "brave-search-mcp"]}}
            }))
            findings = run_agent(root)
            hits = [f for f in findings if f.check_id == "agent.unpinned_mcp_latest_invocation"]
            self.assertEqual(len(hits), 1)

    def test_flags_explicit_latest(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".mcp.json"), json.dumps({
                "mcpServers": {"brave": {"command": "npx", "args": ["-y", "brave-search-mcp@latest"]}}
            }))
            findings = run_agent(root)
            hits = [f for f in findings if f.check_id == "agent.unpinned_mcp_latest_invocation"]
            self.assertEqual(len(hits), 1)

    def test_pinned_version_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".mcp.json"), json.dumps({
                "mcpServers": {"brave": {"command": "npx", "args": ["-y", "brave-search-mcp@2.1.0"]}}
            }))
            findings = run_agent(root)
            hits = [f for f in findings if f.check_id == "agent.unpinned_mcp_latest_invocation"]
            self.assertEqual(hits, [])

    def test_non_npx_command_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".mcp.json"), json.dumps({
                "mcpServers": {"local": {"command": "python3", "args": ["server.py"]}}
            }))
            findings = run_agent(root)
            hits = [f for f in findings if f.check_id == "agent.unpinned_mcp_latest_invocation"]
            self.assertEqual(hits, [])


class TestUnattendedSeparation(unittest.TestCase):
    def test_flags_scheduled_high_impact_profile(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".hermes", "profiles", "trading", "config.yaml"),
                  "cron: '0 9 * * *'\ntools:\n  - trade\n  - bash\n")
            findings = run_agent(root)
            hits = [f for f in findings if f.check_id == "agent.no_interactive_vs_unattended_separation"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].confidence, "low")

    def test_scheduled_without_high_impact_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".hermes", "profiles", "reporter", "config.yaml"),
                  "cron: '0 9 * * *'\ntools:\n  - read\n")
            findings = run_agent(root)
            hits = [f for f in findings if f.check_id == "agent.no_interactive_vs_unattended_separation"]
            self.assertEqual(hits, [])


class TestPromptInjectionReachability(unittest.TestCase):
    def test_flags_untrusted_input_plus_high_impact_no_approval(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".mcp.json"), json.dumps({
                "mcpServers": {
                    "web": {"command": "npx", "args": ["-y", "web-fetch-mcp@1.0.0"]},
                    "shell": {"command": "npx", "args": ["-y", "bash-exec-mcp@1.0.0"]},
                }
            }))
            findings = run_agent(root)
            hits = [f for f in findings if f.check_id == "agent.prompt_injection_reachability"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].confidence, "low")

    def test_approval_marker_suppresses_finding(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".mcp.json"), json.dumps({
                "mcpServers": {
                    "web": {"command": "npx", "args": ["-y", "web-fetch-mcp@1.0.0"]},
                    "shell": {"command": "npx", "args": ["-y", "bash-exec-mcp@1.0.0"], "requireConfirmation": True},
                }
            }))
            findings = run_agent(root)
            hits = [f for f in findings if f.check_id == "agent.prompt_injection_reachability"]
            self.assertEqual(hits, [])

    def test_only_untrusted_input_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".mcp.json"), json.dumps({
                "mcpServers": {"web": {"command": "npx", "args": ["-y", "web-fetch-mcp@1.0.0"]}}
            }))
            findings = run_agent(root)
            hits = [f for f in findings if f.check_id == "agent.prompt_injection_reachability"]
            self.assertEqual(hits, [])


class TestCleanNoFalsePositives(unittest.TestCase):
    def test_clean_config_zero_findings(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), json.dumps({
                "permissions": {"allow": ["Bash(git *)", "Read", "Write"]}
            }))
            write(os.path.join(root, ".mcp.json"), json.dumps({
                "mcpServers": {"notion": {"command": "npx", "args": ["-y", "notion-mcp@1.2.3"]}}
            }))
            findings = run_agent(root)
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
