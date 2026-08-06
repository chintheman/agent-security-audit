import os
import tempfile
import unittest
from unittest import mock

from asa import manifest as manifest_mod
from asa.checkers import network as network_checker
from asa.manifest import Manifest


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def run_network(root, context=None):
    m = manifest_mod.build(root)
    return network_checker.run(m, root, context)


def fake_manifest(root, os_name="Darwin"):
    return Manifest(scan_root=root, scanned_at="2026-01-01T00:00:00Z", host={"os": os_name})


class TestActivation(unittest.TestCase):
    def test_does_not_activate_on_unrelated_project(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "requirements.txt"), "flask\n")
            m = manifest_mod.build(root)
            self.assertFalse(network_checker.activates(m))

    def test_activates_on_docker_compose(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "docker-compose.yml"), "version: '3'\n")
            m = manifest_mod.build(root)
            self.assertTrue(network_checker.activates(m))


class TestBoundAllInterfaces(unittest.TestCase):
    def test_flags_yaml_host_binding(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "docker-compose.yml"), "services:\n  web:\n    host: 0.0.0.0\n")
            findings = run_network(root)
            ids = [f.check_id for f in findings]
            self.assertIn("network.service_bound_all_interfaces", ids)

    def test_flags_cli_flag_style(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "app.service"), "ExecStart=/usr/bin/myapp --host=0.0.0.0 --port 9119\n")
            write(os.path.join(root, "docker-compose.yml"), "version: '3'\n")  # to activate the checker
            findings = run_network(root)
            ids = [f.check_id for f in findings]
            self.assertIn("network.service_bound_all_interfaces", ids)

    def test_does_not_flag_loopback_binding(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "docker-compose.yml"), "services:\n  web:\n    host: 127.0.0.1\n")
            findings = run_network(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("network.service_bound_all_interfaces", ids)

    def test_flags_docker_compose_port_mapping(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "docker-compose.yml"), 'services:\n  web:\n    ports:\n      - "0.0.0.0:8080:80"\n')
            findings = run_network(root)
            ids = [f.check_id for f in findings]
            self.assertIn("network.service_bound_all_interfaces", ids)


class TestTunnelWithoutAccessPolicy(unittest.TestCase):
    def test_flags_loopback_ingress_with_no_access_policy(self):
        with tempfile.TemporaryDirectory() as root:
            write(
                os.path.join(root, ".cloudflared", "config.yml"),
                "tunnel: mytunnel\ningress:\n  - hostname: dash.example.com\n    service: http://localhost:9119\n  - service: http_status:404\n",
            )
            findings = run_network(root)
            ids = [f.check_id for f in findings]
            self.assertIn("network.tunnel_without_access_policy", ids)

    def test_does_not_flag_when_access_policy_present(self):
        with tempfile.TemporaryDirectory() as root:
            write(
                os.path.join(root, ".cloudflared", "config.yml"),
                "tunnel: mytunnel\n# protected by Cloudflare Access\ningress:\n  - hostname: dash.example.com\n    service: http://localhost:9119\n",
            )
            findings = run_network(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("network.tunnel_without_access_policy", ids)

    def test_does_not_flag_non_loopback_target(self):
        with tempfile.TemporaryDirectory() as root:
            write(
                os.path.join(root, ".cloudflared", "config.yml"),
                "tunnel: mytunnel\ningress:\n  - hostname: dash.example.com\n    service: http://internal-server:9119\n",
            )
            findings = run_network(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("network.tunnel_without_access_policy", ids)


class TestDualExposure(unittest.TestCase):
    def test_flags_tls_and_plaintext_port_same_file(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "docker-compose.yml"), "services:\n  ghost:\n    ports:\n      - 443:2368\n      - 10777:2368\n")
            findings = run_network(root)
            ids = [f.check_id for f in findings]
            self.assertIn("network.dual_exposure_http_and_https", ids)

    def test_does_not_flag_tls_only(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "docker-compose.yml"), "services:\n  web:\n    ports:\n      - 443:8443\n")
            findings = run_network(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("network.dual_exposure_http_and_https", ids)


class TestFirewallDisabled(unittest.TestCase):
    def test_macos_disabled_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            m = fake_manifest(root, os_name="Darwin")
            with mock.patch.dict(os.environ, {"HOME": root}), \
                 mock.patch("subprocess.run") as mock_run:
                mock_run.return_value = mock.Mock(returncode=0, stdout="Firewall is disabled. (State = 0)")
                findings = network_checker._check_firewall_disabled(m, root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity.value, "medium")

    def test_macos_enabled_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            m = fake_manifest(root, os_name="Darwin")
            with mock.patch.dict(os.environ, {"HOME": root}), \
                 mock.patch("subprocess.run") as mock_run:
                mock_run.return_value = mock.Mock(returncode=0, stdout="Firewall is enabled. (State = 1)")
                findings = network_checker._check_firewall_disabled(m, root)
            self.assertEqual(findings, [])

    def test_command_unavailable_degrades_to_info_not_crash(self):
        with tempfile.TemporaryDirectory() as root:
            m = fake_manifest(root, os_name="Darwin")
            with mock.patch.dict(os.environ, {"HOME": root}), \
                 mock.patch("subprocess.run", side_effect=FileNotFoundError()):
                findings = network_checker._check_firewall_disabled(m, root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity.value, "info")
            self.assertEqual(findings[0].confidence, "low")

    def test_linux_ufw_disabled_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            m = fake_manifest(root, os_name="Linux")
            with mock.patch.dict(os.environ, {"HOME": root}), \
                 mock.patch("os.path.isfile", return_value=True), \
                 mock.patch("builtins.open", mock.mock_open(read_data="ENABLED=no\n")):
                findings = network_checker._check_firewall_disabled(m, root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity.value, "medium")

    def test_linux_ufw_enabled_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            m = fake_manifest(root, os_name="Linux")
            with mock.patch.dict(os.environ, {"HOME": root}), \
                 mock.patch("os.path.isfile", return_value=True), \
                 mock.patch("builtins.open", mock.mock_open(read_data="ENABLED=yes\n")):
                findings = network_checker._check_firewall_disabled(m, root)
            self.assertEqual(findings, [])

    def test_linux_no_ufw_conf_no_findings(self):
        with tempfile.TemporaryDirectory() as root:
            m = fake_manifest(root, os_name="Linux")
            with mock.patch.dict(os.environ, {"HOME": root}):
                findings = network_checker._check_firewall_disabled(m, root)
            self.assertEqual(findings, [])


class TestScreenLockDisabled(unittest.TestCase):
    def test_macos_no_password_required_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            m = fake_manifest(root, os_name="Darwin")
            with mock.patch.dict(os.environ, {"HOME": root}), \
                 mock.patch("subprocess.run") as mock_run:
                mock_run.return_value = mock.Mock(returncode=0, stdout="0\n")
                findings = network_checker._check_screen_lock_disabled(m, root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].confidence, "medium")

    def test_macos_password_required_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            m = fake_manifest(root, os_name="Darwin")
            with mock.patch.dict(os.environ, {"HOME": root}), \
                 mock.patch("subprocess.run") as mock_run:
                mock_run.return_value = mock.Mock(returncode=0, stdout="1\n")
                findings = network_checker._check_screen_lock_disabled(m, root)
            self.assertEqual(findings, [])

    def test_not_checked_when_scan_root_is_not_home(self):
        with tempfile.TemporaryDirectory() as fake_home, tempfile.TemporaryDirectory() as project:
            m = fake_manifest(project, os_name="Darwin")
            with mock.patch.dict(os.environ, {"HOME": fake_home}):
                findings = network_checker._check_screen_lock_disabled(m, project)
            self.assertEqual(findings, [])


class TestCleanNoFalsePositives(unittest.TestCase):
    def test_clean_docker_compose_only_loopback(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "docker-compose.yml"), 'services:\n  web:\n    ports:\n      - "127.0.0.1:8080:80"\n')
            findings = run_network(root)
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
