import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

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
