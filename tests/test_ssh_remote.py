"""Tests the remote-over-SSH machinery. The highest-value test here runs
the generated bundle script through a REAL `python3 -` subprocess (no SSH
involved, just localhost) -- this proves the module-flattening mechanism
actually works end-to-end, not just that it "looks plausible." Everything
that goes through an actual `ssh` invocation is mocked, per the plan
("mocked SSH transport, no real network").
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from asa import ssh_remote


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


class TestBuildBundleScript(unittest.TestCase):
    def test_produces_nonempty_script(self):
        script = ssh_remote.build_bundle_script()
        self.assertGreater(len(script), 1000)

    def test_includes_every_module_source(self):
        script = ssh_remote.build_bundle_script()
        for mod in ssh_remote._BUNDLE_MODULES:
            self.assertIn(mod.__name__, script)

    def test_is_valid_python_syntax(self):
        script = ssh_remote.build_bundle_script()
        compile(script, "<bundle>", "exec")  # raises SyntaxError if malformed


class TestBundleExecutesForReal(unittest.TestCase):
    """Runs the actual generated bundle through a real python3 subprocess
    -- localhost only, no ssh -- proving the flattening mechanism itself
    is correct, not just well-formed."""

    def _run_bundle_locally(self, scan_root, **request_extra):
        script = ssh_remote.build_bundle_script()
        request = json.dumps({"scan_root": scan_root, "scope": "project", "include_vendored": False, "categories": None, "context": {}, **request_extra})
        proc = subprocess.run(
            [sys.executable, "-", request],
            input=script, capture_output=True, text=True, timeout=60,
        )
        return proc

    def test_clean_target_produces_valid_payload(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hello\n")
            proc = self._run_bundle_locally(root)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = ssh_remote._extract_json_line(proc.stdout)
            self.assertIn("manifest", data)
            self.assertEqual(data["findings"], [])

    def test_vulnerable_target_produces_real_findings(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            proc = self._run_bundle_locally(root)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = ssh_remote._extract_json_line(proc.stdout)
            check_ids = [f["check_id"] for f in data["findings"]]
            self.assertIn("secrets.hardcoded_value_instead_of_env_ref", check_ids)

    def test_all_six_categories_present_in_coverage(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hello\n")
            proc = self._run_bundle_locally(root)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = ssh_remote._extract_json_line(proc.stdout)
            self.assertEqual(len(data["coverage"]), 6)

    def test_output_reconstructs_via_serialize(self):
        from asa.serialize import scan_data_to_objects
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            proc = self._run_bundle_locally(root)
            data = ssh_remote._extract_json_line(proc.stdout)
            manifest, findings, coverage = scan_data_to_objects(data)
            self.assertGreater(len(findings), 0)


class TestExtractJsonLine(unittest.TestCase):
    def test_finds_json_after_banner_text(self):
        stdout = "Welcome to Ubuntu 22.04\nLast login: today\n" + json.dumps({"manifest": {}, "findings": [], "coverage": {}})
        data = ssh_remote._extract_json_line(stdout)
        self.assertEqual(data["findings"], [])

    def test_raises_when_no_valid_json_present(self):
        with self.assertRaises(RuntimeError):
            ssh_remote._extract_json_line("just some banner text\nno json here\n")

    def test_ignores_json_lines_missing_expected_keys(self):
        stdout = json.dumps({"unrelated": True}) + "\n" + json.dumps({"manifest": {}, "findings": [], "coverage": {}})
        data = ssh_remote._extract_json_line(stdout)
        self.assertIn("manifest", data)


class TestRunWithMockedSsh(unittest.TestCase):
    def _fake_payload(self):
        return json.dumps({
            "manifest": {"scan_root": "/home/user/project", "scanned_at": "2026-01-01T00:00:00Z",
                         "components": [], "skipped": [], "unreadable": [], "host": {"os": "Linux"},
                         "walked_top_level": [], "top_level_snapshot": []},
            "findings": [{
                "id": "secrets.x.abc123", "check_id": "secrets.dotenv_world_readable", "category": "secrets",
                "severity": "high", "title": "test finding", "evidence": {}, "fix": "chmod 600",
                "fix_time_estimate": "1 min", "location": "/home/user/project/.env", "confidence": "high",
                "source": "heuristic", "auto_fixable": True, "references": [],
            }],
            "coverage": {"secrets": {"activated": True, "status": "ok", "error": None}},
        })

    def test_invokes_ssh_with_batch_mode_and_pipes_script_via_stdin(self):
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stdout=self._fake_payload(), stderr="")
            ssh_remote.run("user@myhost", scan_root="/home/user/project")
        args, kwargs = mock_run.call_args
        cmd = args[0]
        self.assertIn("ssh", cmd)
        self.assertIn("-o", cmd)
        self.assertIn("BatchMode=yes", cmd)
        self.assertIn("user@myhost", cmd)
        self.assertIn("python3", cmd)
        self.assertTrue(kwargs["input"])  # the bundle script, piped via stdin

    def test_prefixes_finding_locations_with_host(self):
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stdout=self._fake_payload(), stderr="")
            manifest, findings, coverage = ssh_remote.run("user@myhost")
        self.assertTrue(findings[0].location.startswith("user@myhost:"))

    def test_nonzero_exit_raises_with_stderr(self):
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=255, stdout="", stderr="Permission denied (publickey).")
            with self.assertRaises(RuntimeError) as ctx:
                ssh_remote.run("user@myhost")
            self.assertIn("Permission denied", str(ctx.exception))

    def test_timeout_raises_clear_error(self):
        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=5)):
            with self.assertRaises(RuntimeError) as ctx:
                ssh_remote.run("user@myhost", timeout=5)
            self.assertIn("timed out", str(ctx.exception))

    def test_ssh_not_installed_raises_clear_error(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError("no ssh")):
            with self.assertRaises(RuntimeError) as ctx:
                ssh_remote.run("user@myhost")
            self.assertIn("ssh not found", str(ctx.exception))

    def test_garbage_output_raises_rather_than_returning_empty(self):
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stdout="not json at all", stderr="")
            with self.assertRaises(RuntimeError):
                ssh_remote.run("user@myhost")


if __name__ == "__main__":
    unittest.main()
