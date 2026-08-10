import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from asa import exitcodes
from asa.cli import main


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class TestScanCommand(unittest.TestCase):
    def test_clean_target_exit_zero(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hello\n")
            code, out, err = run_cli(["scan", root])
            self.assertEqual(code, exitcodes.CLEAN)
            self.assertIn("Security Audit", out)

    def test_findings_present_exit_one(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            code, out, err = run_cli(["scan", root])
            self.assertEqual(code, exitcodes.FINDINGS_PRESENT)

    def test_nonexistent_path_exit_error(self):
        code, out, err = run_cli(["scan", "/definitely/not/a/real/path/xyz"])
        self.assertEqual(code, exitcodes.ERROR)
        self.assertIn("error", err.lower())

    def test_writes_scan_json_to_asa_output(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            run_cli(["scan", root])
            out_dir = os.path.join(root, "asa-output")
            self.assertTrue(os.path.isdir(out_dir))
            files = os.listdir(out_dir)
            self.assertEqual(len(files), 1)
            with open(os.path.join(out_dir, files[0])) as fh:
                data = json.load(fh)
            self.assertIn("findings", data)
            self.assertIn("manifest", data)
            self.assertIn("dotenv_modes", data)

    def test_html_format(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hello\n")
            code, out, err = run_cli(["scan", root, "--format", "html"])
            self.assertIn("<!doctype html>", out)

    def test_json_format(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hello\n")
            code, out, err = run_cli(["scan", root, "--format", "json"])
            data = json.loads(out)
            self.assertIn("pills", data)

    def test_out_file_writes_instead_of_stdout(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hello\n")
            out_path = os.path.join(root, "report.html")
            code, out, err = run_cli(["scan", root, "--format", "html", "--out", out_path])
            self.assertEqual(out, "")
            self.assertTrue(os.path.isfile(out_path))
            with open(out_path) as fh:
                self.assertIn("<!doctype html>", fh.read())

    def test_category_filter(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            code, out, err = run_cli(["scan", root, "--category", "network", "--format", "json"])
            data = json.loads(out)
            # only the requested category should appear, and it should
            # have found nothing in this secrets-only fixture
            self.assertEqual([s["category"] for s in data["detail_sections"]], ["network"])
            self.assertEqual(data["detail_sections"][0]["findings"], [])

    def test_severity_min_filter(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o644)  # HIGH severity
            write(os.path.join(root, "app.py"), 'X = "' + "AIza" + "q" * 35 + '"\n')  # HIGH too (named provider shape)
            code, out, err = run_cli(["scan", root, "--severity-min", "critical", "--format", "json"])
            data = json.loads(out)
            all_findings = [f for s in data["detail_sections"] for f in s["findings"]]
            self.assertTrue(all(f["severity"] == "Critical" for f in all_findings))


class TestVerboseFlag(unittest.TestCase):
    def test_verbose_shows_detail_in_terminal_output(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            code, out, err = run_cli(["scan", root, "--format", "term"])
            code_v, out_v, err_v = run_cli(["scan", root, "--format", "term", "--verbose"])
            self.assertNotIn("DETAIL BY CATEGORY", out)
            self.assertIn("DETAIL BY CATEGORY", out_v)


class TestBaselineDrift(unittest.TestCase):
    def test_baseline_round_trip_detects_drift(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o600)

            code1, out1, err1 = run_cli(["scan", root, "--format", "json"])
            out_dir = os.path.join(root, "asa-output")
            first_json = os.path.join(out_dir, os.listdir(out_dir)[0])

            os.chmod(path, 0o644)  # simulate a dashboard edit resetting permissions
            code2, out2, err2 = run_cli(["scan", root, "--baseline", first_json, "--format", "json"])

            data2 = json.loads(out2)
            all_findings = [f for s in data2["detail_sections"] for f in s["findings"]]
            self.assertTrue(any(f["title"].startswith(".env") and "loosened" in f["fix"].lower() or "drift" in str(f).lower() or "permission" in f["title"].lower() for f in all_findings) or
                             any("dotenv_permission_drift" in f["id"] for f in all_findings))


class TestReportCommand(unittest.TestCase):
    def test_rerender_from_saved_json(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            run_cli(["scan", root, "--format", "json"])
            out_dir = os.path.join(root, "asa-output")
            saved = os.path.join(out_dir, os.listdir(out_dir)[0])

            code, out, err = run_cli(["report", "--from-json", saved, "--format", "term"])
            self.assertEqual(code, exitcodes.FINDINGS_PRESENT)
            self.assertIn("Security Audit", out)

    def test_rerender_does_not_rescan(self):
        # if the target directory is deleted after scanning, report --from-json
        # must still work since it's reading the saved JSON, not the filesystem
        with tempfile.TemporaryDirectory() as parent:
            root = os.path.join(parent, "target")
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            run_cli(["scan", root, "--format", "json"])
            out_dir = os.path.join(root, "asa-output")
            saved_name = os.listdir(out_dir)[0]

            import shutil
            saved_copy = os.path.join(parent, saved_name)
            shutil.copy(os.path.join(out_dir, saved_name), saved_copy)
            shutil.rmtree(root)

            code, out, err = run_cli(["report", "--from-json", saved_copy, "--format", "term"])
            self.assertEqual(code, exitcodes.FINDINGS_PRESENT)


class TestHostFlag(unittest.TestCase):
    def _fake_remote_result(self):
        from asa.finding import Category, Evidence, Finding, Severity
        from asa.manifest import Manifest
        manifest = Manifest(
            scan_root="/home/user/project", scanned_at="2026-01-01T00:00:00Z",
            components=[], skipped=[], unreadable=[], host={"os": "Linux", "is_remote": True},
            walked_top_level=[], top_level_snapshot=[],
        )
        findings = [Finding(
            check_id="secrets.dotenv_world_readable", category=Category.SECRETS, severity=Severity.HIGH,
            title="test", evidence=Evidence(), fix="chmod 600", location="myhost:/home/user/project/.env",
            auto_fixable=True,
        )]
        coverage = {"secrets": {"activated": True, "status": "ok", "error": None}}
        return manifest, findings, coverage

    def test_host_routes_through_ssh_remote(self):
        with mock.patch("asa.ssh_remote.run") as mock_remote:
            mock_remote.return_value = self._fake_remote_result()
            code, out, err = run_cli(["scan", "--host", "user@myhost", "--format", "json"])
        mock_remote.assert_called_once()
        self.assertEqual(code, exitcodes.FINDINGS_PRESENT)
        self.assertIn("myhost", out)

    def test_host_does_not_require_local_path_to_exist(self):
        # --path defaults to "." but for --host that's a REMOTE path --
        # must not be checked against the local filesystem
        with mock.patch("asa.ssh_remote.run") as mock_remote:
            mock_remote.return_value = self._fake_remote_result()
            code, out, err = run_cli(["scan", "/some/remote/only/path", "--host", "user@myhost", "--format", "json"])
        self.assertNotEqual(code, exitcodes.ERROR)

    def test_remote_failure_reports_cleanly(self):
        with mock.patch("asa.ssh_remote.run", side_effect=RuntimeError("Permission denied (publickey).")):
            code, out, err = run_cli(["scan", "--host", "user@myhost"])
        self.assertEqual(code, exitcodes.ERROR)
        self.assertIn("Permission denied", err)

    def test_fix_refuses_remote_sourced_scan(self):
        with tempfile.TemporaryDirectory() as root:
            manifest, findings, coverage = self._fake_remote_result()
            payload = {
                "manifest": manifest.to_dict(),
                "findings": [f.to_dict() for f in findings],
                "coverage": coverage,
                "dotenv_modes": {},
                "tool_version": "0.1.0",
            }
            saved = os.path.join(root, "remote-scan.json")
            with open(saved, "w") as fh:
                json.dump(payload, fh)

            code, out, err = run_cli(["fix", "--from-json", saved, "--yes"])
            self.assertEqual(code, exitcodes.ERROR)
            self.assertIn("SSH", err)


class TestAiFlag(unittest.TestCase):
    def test_ai_and_host_together_errors(self):
        code, out, err = run_cli(["scan", "--host", "user@myhost", "--ai"])
        self.assertEqual(code, exitcodes.ERROR)
        self.assertIn("--host", err)

    def test_ai_off_by_default_never_imports_ai_assist(self):
        import sys
        sys.modules.pop("asa.ai_assist", None)
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hi\n")
            run_cli(["scan", root])
        self.assertNotIn("asa.ai_assist", sys.modules)

    def test_ai_flag_invokes_ai_assist_and_notes_it_in_output(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hi\n")
            with mock.patch("asa.ai_assist.find_unrecognized_directories", return_value=[]):
                code, out, err = run_cli(["scan", root, "--ai", "--format", "term"])
        self.assertIn("AI-assist", out)

    def test_ai_classification_merges_into_manifest(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "unknownstack", "main.tf"), "")
            fake_guess = {"kind_guess": "terraform_config", "confidence": "medium", "rationale": "looks like terraform"}
            with mock.patch("asa.ai_assist.classify_unknown_component", return_value=fake_guess):
                code, out, err = run_cli(["scan", root, "--ai", "--format", "json"])
            data = json.loads(out)
            self.assertIn("classified 1", data["ai_assist_summary"])

    def test_ai_assist_error_degrades_to_warning_not_crash(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hi\n")
            from asa.ai_assist import AIAssistError
            with mock.patch("asa.ai_assist.find_unrecognized_directories", side_effect=AIAssistError("no API key")):
                code, out, err = run_cli(["scan", root, "--ai"])
            self.assertNotEqual(code, exitcodes.ERROR)
            self.assertIn("no API key", err)


class TestAllowAuditToolsFlag(unittest.TestCase):
    """The flag was documented in README/SECURITY/CONTRIBUTING and honored by
    supply_chain.py via context["allow_audit_tools"] long before argparse
    actually defined it -- so it parsed nowhere and the two audit-tool checks
    were unreachable from the CLI. These tests assert the wiring end to end
    (flag -> context -> checker), not just that the flag parses."""

    def _node_project(self, root):
        write(os.path.join(root, "package.json"), '{"name": "x", "version": "1.0.0"}\n')

    def test_off_by_default_never_runs_audit_tools(self):
        with tempfile.TemporaryDirectory() as root:
            self._node_project(root)
            with mock.patch("asa.checkers.supply_chain._run_npm_audit", return_value=[]) as npm, \
                 mock.patch("asa.checkers.supply_chain._run_pip_audit", return_value=[]) as pip:
                run_cli(["scan", root])
            npm.assert_not_called()
            pip.assert_not_called()

    def test_flag_reaches_the_checker(self):
        with tempfile.TemporaryDirectory() as root:
            self._node_project(root)
            with mock.patch("asa.checkers.supply_chain._run_npm_audit", return_value=[]) as npm, \
                 mock.patch("asa.checkers.supply_chain._run_pip_audit", return_value=[]) as pip:
                run_cli(["scan", root, "--allow-audit-tools"])
            npm.assert_called_once()
            pip.assert_called_once()

    def test_findings_from_audit_tools_reach_the_report(self):
        from asa.finding import Category, Evidence, Finding, Severity
        fake = Finding(
            check_id="supply_chain.npm_audit_findings", category=Category.SUPPLY_CHAIN,
            severity=Severity.HIGH, title="Known vulnerability in leftpad",
            evidence=Evidence(file="package.json", variable_name="leftpad"),
            fix="Upgrade leftpad to 1.2.3", fix_time_estimate="varies",
            location="package.json (leftpad)",
        )
        with tempfile.TemporaryDirectory() as root:
            self._node_project(root)
            with mock.patch("asa.checkers.supply_chain._run_npm_audit", return_value=[fake]), \
                 mock.patch("asa.checkers.supply_chain._run_pip_audit", return_value=[]):
                code, out, err = run_cli(["scan", root, "--allow-audit-tools", "--format", "json"])
            check_ids = [
                f["check_id"]
                for section in json.loads(out)["detail_sections"]
                for f in section["findings"]
            ]
            self.assertIn("supply_chain.npm_audit_findings", check_ids)
            self.assertEqual(code, exitcodes.FINDINGS_PRESENT)


class TestFixCommand(unittest.TestCase):
    def test_dry_run_applies_nothing(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o644)
            run_cli(["scan", root, "--format", "json"])
            out_dir = os.path.join(root, "asa-output")
            saved = os.path.join(out_dir, os.listdir(out_dir)[0])

            code, out, err = run_cli(["fix", "--from-json", saved, "--dry-run"])
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)
            self.assertIn("0/1 fixes applied", out)

    def test_yes_applies_fix(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o644)
            run_cli(["scan", root, "--format", "json"])
            out_dir = os.path.join(root, "asa-output")
            saved = os.path.join(out_dir, os.listdir(out_dir)[0])

            code, out, err = run_cli(["fix", "--from-json", saved, "--yes"])
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertIn("1/1 fixes applied", out)

    def test_nothing_fixable_reports_cleanly(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            run_cli(["scan", root, "--format", "json"])
            out_dir = os.path.join(root, "asa-output")
            saved = os.path.join(out_dir, os.listdir(out_dir)[0])

            code, out, err = run_cli(["fix", "--from-json", saved, "--yes"])
            self.assertIn("Nothing", out)


class TestListChecksCommand(unittest.TestCase):
    def test_lists_secrets_checks(self):
        code, out, err = run_cli(["list-checks"])
        self.assertEqual(code, exitcodes.CLEAN)
        self.assertIn("secrets.hardcoded_value_instead_of_env_ref", out)

    def test_category_filter(self):
        code, out, err = run_cli(["list-checks", "--category", "secrets"])
        for line in out.strip().splitlines():
            self.assertTrue(line.startswith("secrets"))


class TestVersionFlag(unittest.TestCase):
    def test_version_prints_and_exits(self):
        with self.assertRaises(SystemExit) as ctx:
            run_cli(["--version"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
