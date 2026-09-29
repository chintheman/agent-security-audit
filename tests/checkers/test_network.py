import os
import tempfile
import time
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
        # regression: this must mock os.path.isfile like the other two ufw
        # tests do, not rely on ambient filesystem state -- GitHub's own
        # ubuntu-latest CI runners ship ufw pre-installed and disabled by
        # default, so "assume /etc/ufw/ufw.conf doesn't exist" was true on
        # macOS (no ufw at all) but false in CI, and the checker correctly
        # flagged CI's own real ufw.conf as a finding. Caught by CI itself.
        with tempfile.TemporaryDirectory() as root:
            m = fake_manifest(root, os_name="Linux")
            with mock.patch.dict(os.environ, {"HOME": root}), \
                 mock.patch("os.path.isfile", return_value=False):
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


class TestUnauthenticatedDangerousRouteActivation(unittest.TestCase):
    def test_bare_requirements_txt_does_not_activate(self):
        # dependency NAMED in a manifest, no actual route file -- must not
        # activate (regression guard for the existing unrelated-project test)
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "requirements.txt"), "flask\n")
            m = manifest_mod.build(root)
            self.assertFalse(network_checker.activates(m))

    def test_flask_route_file_activates(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "requirements.txt"), "flask\n")
            write(os.path.join(root, "app.py"), "from flask import Flask\napp = Flask(__name__)\n")
            m = manifest_mod.build(root)
            self.assertTrue(network_checker.activates(m))


class TestUnauthenticatedDangerousRoute(unittest.TestCase):
    def test_flags_flask_unauthenticated_shell_exec(self):
        with tempfile.TemporaryDirectory() as root:
            write(
                os.path.join(root, "app.py"),
                "import subprocess\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
                '@app.route("/run", methods=["POST"])\n'
                "def run_command():\n"
                '    cmd = request.args.get("cmd")\n'
                "    return subprocess.run(cmd, shell=True, capture_output=True).stdout\n",
            )
            findings = run_network(root)
            hits = [f for f in findings if f.check_id == "network.unauthenticated_dangerous_route"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].severity.value, "high")
            self.assertEqual(hits[0].confidence, "low")
            self.assertEqual(hits[0].evidence.detail["sink_kind"], "command_execution")

    def test_does_not_flag_route_with_login_required(self):
        with tempfile.TemporaryDirectory() as root:
            write(
                os.path.join(root, "app.py"),
                "import subprocess\nfrom flask import Flask, request\nfrom auth import login_required\n"
                "app = Flask(__name__)\n\n"
                '@app.route("/run", methods=["POST"])\n'
                "@login_required\n"
                "def run_command():\n"
                '    cmd = request.args.get("cmd")\n'
                "    return subprocess.run(cmd, shell=True, capture_output=True).stdout\n",
            )
            findings = run_network(root)
            hits = [f for f in findings if f.check_id == "network.unauthenticated_dangerous_route"]
            self.assertEqual(hits, [])

    def test_does_not_flag_route_without_dangerous_sink(self):
        with tempfile.TemporaryDirectory() as root:
            write(
                os.path.join(root, "app.py"),
                "from flask import Flask, request\napp = Flask(__name__)\n\n"
                '@app.route("/echo")\n'
                "def echo():\n"
                '    return request.args.get("msg")\n',
            )
            findings = run_network(root)
            hits = [f for f in findings if f.check_id == "network.unauthenticated_dangerous_route"]
            self.assertEqual(hits, [])

    def test_flags_express_unauthenticated_exec(self):
        with tempfile.TemporaryDirectory() as root:
            write(
                os.path.join(root, "server.js"),
                'const express = require("express");\n'
                'const { exec } = require("child_process");\n'
                "const app = express();\n\n"
                'app.post("/run", (req, res) => {\n'
                "  const cmd = req.body.cmd;\n"
                "  exec(cmd, (err, stdout) => {\n"
                "    res.send(stdout);\n"
                "  });\n"
                "});\n",
            )
            findings = run_network(root)
            hits = [f for f in findings if f.check_id == "network.unauthenticated_dangerous_route"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].evidence.detail["sink_kind"], "command_execution")

    def test_does_not_flag_express_route_behind_app_wide_middleware(self):
        with tempfile.TemporaryDirectory() as root:
            write(
                os.path.join(root, "server.js"),
                'const express = require("express");\n'
                'const { exec } = require("child_process");\n'
                'const { requireAuth } = require("./auth");\n'
                "const app = express();\n"
                "app.use(requireAuth);\n\n"
                'app.post("/run", (req, res) => {\n'
                "  const cmd = req.body.cmd;\n"
                "  exec(cmd, (err, stdout) => {\n"
                "    res.send(stdout);\n"
                "  });\n"
                "});\n",
            )
            findings = run_network(root)
            hits = [f for f in findings if f.check_id == "network.unauthenticated_dangerous_route"]
            self.assertEqual(hits, [])

    def test_fixture_project_on_disk(self):
        fixture_root = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "fixtures", "dangerous_routes_project"
        )
        findings = run_network(fixture_root)
        hits = [f for f in findings if f.check_id == "network.unauthenticated_dangerous_route"]
        locations = sorted(f.location for f in hits)
        # exactly the two unauthenticated routes -- unsafe_app.py's clean
        # /status route and safe_app.py / protected_server.js must stay silent
        self.assertEqual(locations, ["server.js:6", "unsafe_app.py:8"])


class TestServiceWithoutAccessLog(unittest.TestCase):
    def _ingress(self, root, target="http://localhost:9119"):
        write(
            os.path.join(root, ".cloudflared", "config.yml"),
            f"tunnel: mytunnel\ningress:\n  - hostname: dash.example.com\n    service: {target}\n  - service: http_status:404\n",
        )

    def _hits(self, findings):
        return [f for f in findings if f.check_id == "network.internet_facing_service_without_access_log"]

    def test_flags_loopback_ingress_without_access_log(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.dict(os.environ, {"HOME": root}):
            self._ingress(root)
            findings = run_network(root)
            hits = self._hits(findings)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].severity.value, "medium")
            self.assertTrue(hits[0].fix_time_estimate)

    def test_no_finding_when_access_log_exists_and_fresh(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.dict(os.environ, {"HOME": root}):
            self._ingress(root)
            write(os.path.join(root, ".hermes", "logs", "access.jsonl"), '{"origin":"hermes-web"}\n')
            os.utime(os.path.join(root, ".hermes", "logs", "access.jsonl"), None)  # now
            findings = run_network(root)
            self.assertEqual(self._hits(findings), [])

    def test_flags_when_access_log_stale_beyond_window(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.dict(os.environ, {"HOME": root}):
            self._ingress(root)
            log = os.path.join(root, ".hermes", "logs", "access.jsonl")
            write(log, '{"origin":"hermes-web"}\n')
            old = time.time() - 10 * 86400
            os.utime(log, (old, old))
            findings = run_network(root)
            hits = self._hits(findings)
            self.assertEqual(len(hits), 1)
            self.assertFalse(hits[0].evidence.detail["log_fresh"])

    def test_info_finding_when_source_marker_present_but_no_live_log(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as fake_home, \
             mock.patch.dict(os.environ, {"HOME": fake_home}):
            self._ingress(root)
            write(
                os.path.join(root, "web_server.py"),
                'from fastapi import FastAPI\napp = FastAPI()\n@app.middleware("http")\nasync def log_mw(request, call_next):\n    ua = request.headers.get("user-agent", "")\n',
            )
            findings = run_network(root)
            hits = self._hits(findings)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].severity.value, "info")
            self.assertEqual(hits[0].confidence, "low")

    def test_does_not_flag_non_loopback_target(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.dict(os.environ, {"HOME": root}):
            self._ingress(root, target="http://internal-server:9119")
            findings = run_network(root)
            self.assertEqual(self._hits(findings), [])


if __name__ == "__main__":
    unittest.main()
