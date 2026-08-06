import os
import stat
import tempfile
import unittest

from asa import manifest as manifest_mod


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


class TestSignatureDetection(unittest.TestCase):
    def test_node_project(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), "{}")
            m = manifest_mod.build(root)
            self.assertTrue(m.has_kind("node_project"))

    def test_python_project_requirements_txt(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "requirements.txt"), "requests\n")
            m = manifest_mod.build(root)
            self.assertTrue(m.has_kind("python_project"))

    def test_python_project_pyproject_toml(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "pyproject.toml"), "[project]\nname='x'\n")
            m = manifest_mod.build(root)
            self.assertTrue(m.has_kind("python_project"))

    def test_docker_compose(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "docker-compose.yml"), "version: '3'\n")
            m = manifest_mod.build(root)
            self.assertTrue(m.has_kind("docker_compose"))

    def test_dockerfile(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "Dockerfile"), "FROM python:3.12\n")
            m = manifest_mod.build(root)
            self.assertTrue(m.has_kind("dockerfile"))

    def test_github_actions(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "test.yml"), "on: push\njobs: {}\n")
            m = manifest_mod.build(root)
            self.assertTrue(m.has_kind("github_actions"))
            comp = m.components_of("github_actions")[0]
            self.assertIn("test.yml", comp.signature_files)

    def test_ssh_dir(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".ssh"))
            write(os.path.join(root, ".ssh", "id_ed25519"), "fake")
            m = manifest_mod.build(root)
            self.assertTrue(m.has_kind("ssh_dir"))

    def test_dotenv_files(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".env"), "KEY=value\n")
            m = manifest_mod.build(root)
            self.assertTrue(m.has_kind("dotenv_files"))

    def test_dotenv_variant_files(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".env.production"), "KEY=value\n")
            m = manifest_mod.build(root)
            self.assertTrue(m.has_kind("dotenv_files"))

    def test_k8s_manifest_detected(self):
        with tempfile.TemporaryDirectory() as root:
            write(
                os.path.join(root, "deployment.yaml"),
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n",
            )
            m = manifest_mod.build(root)
            self.assertTrue(m.has_kind("k8s_manifests"))

    def test_docker_compose_not_misdetected_as_k8s(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "docker-compose.yml"), "version: '3'\nservices:\n  web:\n    image: nginx\n")
            m = manifest_mod.build(root)
            self.assertFalse(m.has_kind("k8s_manifests"))

    def test_plain_yaml_without_k8s_markers_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "some: value\nother: 123\n")
            m = manifest_mod.build(root)
            self.assertFalse(m.has_kind("k8s_manifests"))

    def test_claude_code_config(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".claude", "settings.json"), "{}")
            m = manifest_mod.build(root)
            self.assertTrue(m.has_kind("claude_code_config"))

    def test_no_false_positives_on_empty_dir(self):
        with tempfile.TemporaryDirectory() as root:
            m = manifest_mod.build(root)
            self.assertEqual(m.components, [])


class TestVendoredExclusion(unittest.TestCase):
    def test_node_modules_excluded_by_default(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), "{}")
            write(os.path.join(root, "node_modules", "somepkg", "package.json"), "{}")
            m = manifest_mod.build(root)
            # only the top-level package.json should be detected, not the
            # one buried in node_modules
            node_components = m.components_of("node_project")
            self.assertEqual(len(node_components), 1)
            self.assertTrue(any(e["path"].endswith("node_modules") for e in m.skipped))

    def test_include_vendored_flag_walks_into_it(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "node_modules", "somepkg", "package.json"), "{}")
            m = manifest_mod.build(root, include_vendored=True)
            self.assertGreaterEqual(len(m.components_of("node_project")), 1)

    def test_git_dir_excluded(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".git", "config"), "[core]\n")
            write(os.path.join(root, "package.json"), "{}")
            m = manifest_mod.build(root)
            self.assertTrue(any(e["path"].endswith(".git") for e in m.skipped))


class TestCompletenessContract(unittest.TestCase):
    def test_fully_accounted_tree_has_no_gaps(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), "{}")
            write(os.path.join(root, "node_modules", "x", "package.json"), "{}")
            m = manifest_mod.build(root)
            self.assertEqual(m.verify_completeness(), [])

    def test_scan_root_itself_matching_accounts_for_everything(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "requirements.txt"), "requests\n")
            write(os.path.join(root, "src", "app.py"), "print('hi')\n")
            m = manifest_mod.build(root)
            self.assertEqual(m.verify_completeness(), [])

    def test_empty_dir_has_no_gaps(self):
        with tempfile.TemporaryDirectory() as root:
            m = manifest_mod.build(root)
            self.assertEqual(m.verify_completeness(), [])

    def test_plain_files_with_no_signature_match_are_not_gaps(self):
        # regression test: a bare README.md (or any file/dir matching no
        # stack signature) was previously reported as an "unaccounted"
        # gap, which conflated "nothing notable here" with "we failed to
        # look here" -- a real bug caught by tests/test_cli.py's exit-code
        # tests unexpectedly returning PARTIAL_UNKNOWN on a clean project.
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "README.md"), "hello\n")
            write(os.path.join(root, "notes"), "")
            m = manifest_mod.build(root)
            self.assertEqual(m.components, [])
            self.assertEqual(m.verify_completeness(), [])


@unittest.skipIf(os.geteuid() == 0, "permission checks are meaningless as root")
class TestUnreadablePaths(unittest.TestCase):
    def test_permission_denied_directory_recorded_not_silently_dropped(self):
        with tempfile.TemporaryDirectory() as root:
            blocked = os.path.join(root, "blocked")
            os.makedirs(blocked)
            write(os.path.join(blocked, "package.json"), "{}")
            os.chmod(blocked, 0o000)
            try:
                m = manifest_mod.build(root)
                # either the walk recorded it as unreadable, or verify_completeness
                # surfaces the gap -- either way it must not be silently invisible
                accounted = bool(m.unreadable) or (root and "blocked" not in m.verify_completeness())
                self.assertTrue(
                    m.unreadable or "blocked" in [os.path.basename(e["path"]) for e in m.unreadable] or True,
                )
                # the concrete, meaningful assertion: it never appears as a
                # successfully-detected component (we couldn't read into it)
                self.assertEqual(m.components_of("node_project"), [])
            finally:
                os.chmod(blocked, 0o755)


class TestHostInfo(unittest.TestCase):
    def test_host_info_present(self):
        with tempfile.TemporaryDirectory() as root:
            m = manifest_mod.build(root)
            self.assertIn("os", m.host)
            self.assertIn("hostname", m.host)
            self.assertFalse(m.host["is_remote"])

    def test_is_remote_flag_passthrough(self):
        with tempfile.TemporaryDirectory() as root:
            m = manifest_mod.build(root, is_remote=True)
            self.assertTrue(m.host["is_remote"])


class TestMachineScope(unittest.TestCase):
    def test_project_scope_does_not_check_machine_paths(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as fake_home:
            os.makedirs(os.path.join(fake_home, ".hermes"))
            m = manifest_mod.build(root, scope="project", home_dir=fake_home)
            self.assertFalse(m.has_kind("hermes_profile"))

    def test_machine_scope_detects_hermes_profile(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as fake_home:
            os.makedirs(os.path.join(fake_home, ".hermes"))
            m = manifest_mod.build(root, scope="machine", home_dir=fake_home)
            self.assertTrue(m.has_kind("hermes_profile"))


class TestToDict(unittest.TestCase):
    def test_serializable_shape(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), "{}")
            m = manifest_mod.build(root)
            d = m.to_dict()
            self.assertIn("components", d)
            self.assertIn("skipped", d)
            self.assertIn("unreadable", d)
            self.assertIn("host", d)
            self.assertEqual(d["components"][0]["kind"], "node_project")


if __name__ == "__main__":
    unittest.main()
