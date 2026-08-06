import os
import subprocess
import tempfile
import unittest
from unittest import mock

from asa import manifest as manifest_mod
from asa.checkers import permissions as permissions_checker

HAS_SSH_KEYGEN = subprocess.run(["which", "ssh-keygen"], capture_output=True).returncode == 0


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def run_permissions(root, context=None):
    m = manifest_mod.build(root)
    return permissions_checker.run(m, root, context)


def gen_key(path, passphrase=""):
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", path, "-N", passphrase, "-C", "test"],
        capture_output=True, check=True,
    )


class TestActivation(unittest.TestCase):
    def test_does_not_activate_on_unrelated_project(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), "{}")
            m = manifest_mod.build(root)
            self.assertFalse(permissions_checker.activates(m))

    def test_activates_when_ssh_dir_present(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".ssh"))
            m = manifest_mod.build(root)
            self.assertTrue(permissions_checker.activates(m))


@unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen not installed")
class TestSshKeyChecks(unittest.TestCase):
    def test_flags_key_with_no_passphrase(self):
        with tempfile.TemporaryDirectory() as root:
            ssh_dir = os.path.join(root, ".ssh")
            os.makedirs(ssh_dir)
            key_path = os.path.join(ssh_dir, "id_ed25519")
            gen_key(key_path, passphrase="")
            os.chmod(key_path, 0o600)
            findings = run_permissions(root)
            ids = [f.check_id for f in findings]
            self.assertIn("permissions.ssh_private_key_no_passphrase", ids)

    def test_does_not_flag_key_with_passphrase(self):
        with tempfile.TemporaryDirectory() as root:
            ssh_dir = os.path.join(root, ".ssh")
            os.makedirs(ssh_dir)
            key_path = os.path.join(ssh_dir, "id_ed25519")
            gen_key(key_path, passphrase="correcthorsebatterystaple")
            os.chmod(key_path, 0o600)
            findings = run_permissions(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("permissions.ssh_private_key_no_passphrase", ids)

    def test_flags_permissive_mode(self):
        with tempfile.TemporaryDirectory() as root:
            ssh_dir = os.path.join(root, ".ssh")
            os.makedirs(ssh_dir)
            key_path = os.path.join(ssh_dir, "id_ed25519")
            gen_key(key_path, passphrase="correcthorsebatterystaple")
            os.chmod(key_path, 0o644)
            findings = run_permissions(root)
            hits = [f for f in findings if f.check_id == "permissions.ssh_private_key_permissive_mode"]
            self.assertEqual(len(hits), 1)
            self.assertTrue(hits[0].auto_fixable)

    def test_public_key_file_not_treated_as_private_key(self):
        with tempfile.TemporaryDirectory() as root:
            ssh_dir = os.path.join(root, ".ssh")
            os.makedirs(ssh_dir)
            key_path = os.path.join(ssh_dir, "id_ed25519")
            gen_key(key_path, passphrase="correcthorsebatterystaple")
            os.chmod(key_path + ".pub", 0o644)  # public keys are supposed to be world-readable
            findings = run_permissions(root)
            for f in findings:
                self.assertNotIn(".pub", f.location)

    def test_ssh_config_world_readable_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            ssh_dir = os.path.join(root, ".ssh")
            os.makedirs(ssh_dir)
            config_path = os.path.join(ssh_dir, "config")
            write(config_path, "Host *\n  UseKeychain yes\n")
            os.chmod(config_path, 0o644)
            findings = run_permissions(root)
            hits = [f for f in findings if f.check_id == "permissions.sensitive_file_world_readable"]
            self.assertEqual(len(hits), 1)


class TestHomeDirectoryChecks(unittest.TestCase):
    def test_permissive_home_flagged_when_scanning_home(self):
        with tempfile.TemporaryDirectory() as fake_home:
            write(os.path.join(fake_home, "README.md"), "hi\n")
            os.chmod(fake_home, 0o755)
            with mock.patch.dict(os.environ, {"HOME": fake_home}):
                findings = run_permissions(fake_home)
            hits = [f for f in findings if f.check_id == "permissions.home_directory_too_permissive"]
            self.assertEqual(len(hits), 1)

    def test_tight_home_not_flagged(self):
        with tempfile.TemporaryDirectory() as fake_home:
            write(os.path.join(fake_home, "README.md"), "hi\n")
            os.chmod(fake_home, 0o700)
            with mock.patch.dict(os.environ, {"HOME": fake_home}):
                findings = run_permissions(fake_home)
            hits = [f for f in findings if f.check_id == "permissions.home_directory_too_permissive"]
            self.assertEqual(hits, [])

    def test_not_checked_when_scan_root_is_not_home(self):
        with tempfile.TemporaryDirectory() as fake_home, tempfile.TemporaryDirectory() as project:
            os.chmod(fake_home, 0o755)
            write(os.path.join(project, "README.md"), "hi\n")
            with mock.patch.dict(os.environ, {"HOME": fake_home}):
                m = manifest_mod.build(project)
                findings = permissions_checker.run(m, project, None)
            hits = [f for f in findings if f.check_id == "permissions.home_directory_too_permissive"]
            self.assertEqual(hits, [])


class TestUmaskChecks(unittest.TestCase):
    def test_weak_umask_flagged(self):
        with tempfile.TemporaryDirectory() as fake_home:
            write(os.path.join(fake_home, ".zshrc"), "umask 022\n")
            with mock.patch.dict(os.environ, {"HOME": fake_home}):
                findings = run_permissions(fake_home)
            hits = [f for f in findings if f.check_id == "permissions.insecure_default_umask" and f.severity.value != "info"]
            self.assertEqual(len(hits), 1)

    def test_strict_umask_not_flagged(self):
        with tempfile.TemporaryDirectory() as fake_home:
            write(os.path.join(fake_home, ".zshrc"), "umask 077\n")
            with mock.patch.dict(os.environ, {"HOME": fake_home}):
                findings = run_permissions(fake_home)
            hits = [f for f in findings if f.check_id == "permissions.insecure_default_umask" and f.severity.value != "info"]
            self.assertEqual(hits, [])

    def test_no_umask_setting_yields_info_not_silence(self):
        with tempfile.TemporaryDirectory() as fake_home:
            write(os.path.join(fake_home, "README.md"), "hi\n")
            with mock.patch.dict(os.environ, {"HOME": fake_home}):
                findings = run_permissions(fake_home)
            hits = [f for f in findings if f.check_id == "permissions.insecure_default_umask"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].severity.value, "info")


class TestCleanNoFalsePositives(unittest.TestCase):
    def test_unrelated_project_zero_findings(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), "{}")
            m = manifest_mod.build(root)
            self.assertFalse(permissions_checker.activates(m))


if __name__ == "__main__":
    unittest.main()
