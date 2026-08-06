import json
import os
import tempfile
import unittest

from asa import fixer
from asa.finding import Category, Evidence, Finding, Severity


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def make_finding(check_id, path, category=Category.SECRETS):
    return Finding(
        check_id=check_id, category=category, severity=Severity.HIGH,
        title=f"finding for {path}", evidence=Evidence(file=path),
        fix="chmod 600", location=path, auto_fixable=True,
    )


class TestIsAutoFixable(unittest.TestCase):
    def test_known_check_ids(self):
        for cid in fixer.SAFE_FIX_ALLOWLIST:
            self.assertTrue(fixer.is_auto_fixable(cid))

    def test_unknown_check_id(self):
        self.assertFalse(fixer.is_auto_fixable("secrets.hardcoded_value_instead_of_env_ref"))

    def test_allowlist_is_narrow_and_chmod_only(self):
        self.assertEqual(len(fixer.SAFE_FIX_ALLOWLIST), 3)
        for spec in fixer.SAFE_FIX_ALLOWLIST.values():
            self.assertEqual(spec["action"], "chmod")


class TestApplyDryRun(unittest.TestCase):
    def test_dry_run_does_not_change_mode(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o644)
            f = make_finding("secrets.dotenv_world_readable", path)
            results = fixer.apply([f], mode="dry-run")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)
            self.assertFalse(results[0].applied)
            self.assertEqual(results[0].skipped_reason, "dry-run")


class TestApplyAskEach(unittest.TestCase):
    def test_yes_applies_fix(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o644)
            f = make_finding("secrets.dotenv_world_readable", path)
            results = fixer.apply([f], mode="ask-each", input_func=lambda p: "y", print_func=lambda m: None)
            self.assertTrue(results[0].applied)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(results[0].old_mode, 0o644)
            self.assertEqual(results[0].new_mode, 0o600)

    def test_no_declines_fix(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o644)
            f = make_finding("secrets.dotenv_world_readable", path)
            results = fixer.apply([f], mode="ask-each", input_func=lambda p: "n", print_func=lambda m: None)
            self.assertFalse(results[0].applied)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)
            self.assertEqual(results[0].skipped_reason, "declined")

    def test_all_applies_remaining_without_further_prompts(self):
        with tempfile.TemporaryDirectory() as root:
            paths = []
            findings = []
            for i in range(3):
                p = os.path.join(root, f"f{i}.env")
                write(p, "KEY=value\n")
                os.chmod(p, 0o644)
                paths.append(p)
                findings.append(make_finding("secrets.dotenv_world_readable", p))
            prompts = []

            def fake_input(prompt):
                prompts.append(prompt)
                return "a"

            results = fixer.apply(findings, mode="ask-each", input_func=fake_input, print_func=lambda m: None)
            self.assertEqual(len(prompts), 1)  # only asked once, then auto-applied the rest
            self.assertTrue(all(r.applied for r in results))
            for p in paths:
                self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)

    def test_quit_stops_remaining(self):
        with tempfile.TemporaryDirectory() as root:
            findings = []
            for i in range(3):
                p = os.path.join(root, f"f{i}.env")
                write(p, "KEY=value\n")
                os.chmod(p, 0o644)
                findings.append(make_finding("secrets.dotenv_world_readable", p))
            results = fixer.apply(findings, mode="ask-each", input_func=lambda p: "q", print_func=lambda m: None)
            self.assertEqual(results, [])


class TestApplyYesMode(unittest.TestCase):
    def test_yes_mode_never_prompts(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o644)
            f = make_finding("secrets.dotenv_world_readable", path)

            def should_not_be_called(prompt):
                raise AssertionError("input_func must not be called in yes mode")

            results = fixer.apply([f], mode="yes", input_func=should_not_be_called, print_func=lambda m: None)
            self.assertTrue(results[0].applied)


class TestSafetyGuards(unittest.TestCase):
    def test_ignores_findings_outside_allowlist(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "config.yaml")
            write(path, "PASSWORD: literal\n")
            f = make_finding("secrets.hardcoded_value_instead_of_env_ref", path)
            results = fixer.apply([f], mode="yes")
            self.assertEqual(results, [])  # not fixable, never touched

    def test_missing_file_skipped_not_crashed(self):
        f = make_finding("secrets.dotenv_world_readable", "/definitely/not/a/real/path.env")
        results = fixer.apply([f], mode="yes")
        self.assertFalse(results[0].applied)
        self.assertIn("not a regular file", results[0].skipped_reason)

    def test_directory_never_touched(self):
        with tempfile.TemporaryDirectory() as root:
            subdir = os.path.join(root, "somedir")
            os.makedirs(subdir)
            f = make_finding("secrets.dotenv_world_readable", subdir)
            results = fixer.apply([f], mode="yes")
            self.assertFalse(results[0].applied)

    def test_symlink_never_touched(self):
        with tempfile.TemporaryDirectory() as root:
            real = os.path.join(root, "real.env")
            write(real, "KEY=value\n")
            link = os.path.join(root, "link.env")
            os.symlink(real, link)
            f = make_finding("secrets.dotenv_world_readable", link)
            results = fixer.apply([f], mode="yes")
            self.assertFalse(results[0].applied)
            self.assertIn("symlink", results[0].skipped_reason)

    def test_ignores_finding_field_auto_fixable_override(self):
        """Defense-in-depth: even if a Finding claims auto_fixable=True for
        a check_id NOT in the allowlist (e.g. a buggy checker), fixer.py
        must not trust that stored field -- it re-derives fixability from
        check_id alone."""
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "config.yaml")
            write(path, "PASSWORD: literal\n")
            f = Finding(
                check_id="secrets.hardcoded_value_instead_of_env_ref", category=Category.SECRETS,
                severity=Severity.HIGH, title="x", evidence=Evidence(),
                fix="x", location=path, auto_fixable=True,  # lying about it
            )
            results = fixer.apply([f], mode="yes")
            self.assertEqual(results, [])


class TestFixLog(unittest.TestCase):
    def test_writes_log_with_revert_commands(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o644)
            f = make_finding("secrets.dotenv_world_readable", path)
            log_dir = os.path.join(root, "asa-output")
            fixer.apply([f], mode="yes", log_dir=log_dir)

            files = os.listdir(log_dir)
            self.assertEqual(len(files), 1)
            with open(os.path.join(log_dir, files[0])) as fh:
                data = json.load(fh)
            self.assertEqual(len(data["results"]), 1)
            self.assertTrue(data["results"][0]["applied"])
            self.assertIn("chmod 644", data["revert_commands"][0])


if __name__ == "__main__":
    unittest.main()
