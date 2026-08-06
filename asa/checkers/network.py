"""Network/service exposure checks. Five checks:
  1. service_bound_all_interfaces -- 0.0.0.0 bind instead of loopback
  2. tunnel_without_access_policy -- Cloudflare Tunnel ingress to a loopback
     service with no access policy alongside it
  3. dual_exposure_http_and_https -- same service on both a TLS and a
     plaintext port
  4. firewall_disabled -- best-effort OS check (config file where one
     exists, a read-only local command otherwise)
  5. screen_lock_disabled -- best-effort, always lower confidence

Best-effort checks are marked confidence="medium" or lower and never crash
if the underlying command/file isn't available -- they degrade to "unknown,
verify manually" rather than silently claiming a clean result.
"""

from __future__ import annotations

import os
import re
import subprocess

from asa.finding import Category, Evidence, Finding, Severity
from asa.manifest import iter_files

CATEGORY = Category.NETWORK
CHECK_IDS = [
    "network.service_bound_all_interfaces",
    "network.tunnel_without_access_policy",
    "network.dual_exposure_http_and_https",
    "network.firewall_disabled",
    "network.screen_lock_disabled",
]

BIND_ALL_PATTERNS = [
    re.compile(r"host\s*[:=]\s*[\"']?0\.0\.0\.0[\"']?", re.IGNORECASE),
    re.compile(r"--host[= ]0\.0\.0\.0"),
    re.compile(r"bind\s*[:=]\s*[\"']?0\.0\.0\.0[\"']?", re.IGNORECASE),
    re.compile(r"[\"']?0\.0\.0\.0[\"']?:\d+:\d+"),  # docker-compose "0.0.0.0:8080:80"
]
CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".cfg", ".service", ".env"}


def activates(manifest) -> bool:
    return (
        manifest.has_kind("docker_compose")
        or manifest.has_kind("cloudflared_config")
        or _home_is_scan_root(manifest)
    )


def _home_is_scan_root(manifest) -> bool:
    home = os.path.expanduser("~")
    try:
        return os.path.realpath(manifest.scan_root) == os.path.realpath(home)
    except OSError:
        return False


def _check_bound_all_interfaces(manifest, root) -> list:
    findings = []
    seen_locations = set()
    for filepath in iter_files(root):
        ext = os.path.splitext(filepath)[1]
        if ext not in CONFIG_EXTENSIONS:
            continue
        try:
            if os.path.getsize(filepath) > 500_000:
                continue
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        for i, line in enumerate(lines, start=1):
            if any(p.search(line) for p in BIND_ALL_PATTERNS):
                loc = f"{os.path.relpath(filepath, root)}:{i}"
                if loc in seen_locations:
                    continue
                seen_locations.add(loc)
                findings.append(Finding(
                    check_id="network.service_bound_all_interfaces",
                    category=CATEGORY, severity=Severity.HIGH,
                    title="Service appears bound to all interfaces (0.0.0.0) instead of loopback",
                    evidence=Evidence(file=os.path.relpath(filepath, root), line=i, snippet=line.strip()[:160]),
                    fix="Bind to 127.0.0.1 unless this genuinely needs to be reachable from other machines. If it does, put an auth layer in front of it.",
                    fix_time_estimate="10 min", location=loc,
                ))
    return findings


def _check_tunnel_without_access_policy(manifest, root) -> list:
    findings = []
    for comp in manifest.components_of("cloudflared_config"):
        comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        for fname in comp.signature_files:
            path = os.path.join(comp_dir, fname)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue
            if "ingress:" not in content:
                continue
            has_loopback_target = bool(re.search(r"service:\s*https?://(127\.0\.0\.1|localhost)", content))
            has_access_policy = "access" in content.lower() or "cloudflareaccess" in content.lower()
            if has_loopback_target and not has_access_policy:
                findings.append(Finding(
                    check_id="network.tunnel_without_access_policy",
                    category=CATEGORY, severity=Severity.MEDIUM,
                    title=f"{fname} tunnels a local service to the internet with no access policy visible",
                    evidence=Evidence(file=os.path.relpath(path, root) if path.startswith(root) else path),
                    fix="Put a Cloudflare Access policy (or equivalent auth) in front of this ingress rule, or confirm the service handles its own auth.",
                    fix_time_estimate="15 min", location=path, confidence="medium",
                ))
    return findings


def _check_dual_exposure(manifest, root) -> list:
    """Best-effort: look for the same host:port-ish service name/pattern
    registered on both a TLS-typical port (443/8443) and a plaintext port
    (80/8080/8000) within the same config file -- catches the shape of the
    real audit finding (a service correctly served over HTTPS also
    reachable over plaintext on a different port) without needing a live
    network probe."""
    findings = []
    tls_ports = {"443", "8443"}
    plain_ports = {"80", "8080", "8000", "10777"}
    # two shapes worth catching: a compose-style "HOST:CONTAINER" mapping
    # (captures both numbers -- "443:2368" must register 443, not just the
    # container-side 2368), and a bare ":NNNN" bind/listen pattern.
    pair_pattern = re.compile(r"\b(\d{2,5}):(\d{2,5})\b")
    single_pattern = re.compile(r":(\d{2,5})\b")

    for filepath in iter_files(root):
        ext = os.path.splitext(filepath)[1]
        if ext not in CONFIG_EXTENSIONS:
            continue
        try:
            if os.path.getsize(filepath) > 500_000:
                continue
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        ports_found = set(single_pattern.findall(content))
        for a, b in pair_pattern.findall(content):
            ports_found.add(a)
            ports_found.add(b)
        if ports_found & tls_ports and ports_found & plain_ports:
            findings.append(Finding(
                check_id="network.dual_exposure_http_and_https",
                category=CATEGORY, severity=Severity.MEDIUM,
                title=f"{os.path.basename(filepath)} references both a TLS port and a plaintext port for what looks like the same service",
                evidence=Evidence(file=os.path.relpath(filepath, root), detail={"tls_ports": sorted(ports_found & tls_ports), "plain_ports": sorted(ports_found & plain_ports)}),
                fix="Confirm the plaintext port isn't serving the same content/login form as the TLS port. If it is, terminate TLS there too or disable it.",
                fix_time_estimate="15 min", location=os.path.relpath(filepath, root), confidence="medium",
            ))
    return findings


def _check_firewall_disabled(manifest, root) -> list:
    if not _home_is_scan_root(manifest):
        return []
    os_name = manifest.host.get("os", "")

    if os_name == "Linux":
        ufw_conf = "/etc/ufw/ufw.conf"
        if os.path.isfile(ufw_conf):
            try:
                with open(ufw_conf, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                return []
            if re.search(r"^\s*ENABLED\s*=\s*no", content, re.MULTILINE | re.IGNORECASE):
                return [Finding(
                    check_id="network.firewall_disabled",
                    category=CATEGORY, severity=Severity.MEDIUM,
                    title="ufw firewall is disabled",
                    evidence=Evidence(file=ufw_conf),
                    fix="sudo ufw enable",
                    fix_time_estimate="1 min", location=ufw_conf,
                )]
        return []

    if os_name == "Darwin":
        try:
            proc = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return [_unknown_firewall_finding()]
        if proc.returncode != 0:
            return [_unknown_firewall_finding()]
        if "disabled" in proc.stdout.lower():
            return [Finding(
                check_id="network.firewall_disabled",
                category=CATEGORY, severity=Severity.MEDIUM,
                title="macOS application firewall is disabled",
                evidence=Evidence(detail={"checked_via": "socketfilterfw --getglobalstate"}),
                fix="System Settings -> Network -> Firewall -> On (or `sudo socketfilterfw --setglobalstate on`).",
                fix_time_estimate="1 min", location="socketfilterfw",
            )]
        return []

    return []


def _unknown_firewall_finding() -> Finding:
    return Finding(
        check_id="network.firewall_disabled",
        category=CATEGORY, severity=Severity.INFO,
        title="Could not determine firewall state automatically",
        evidence=Evidence(),
        fix="Check manually: System Settings -> Network -> Firewall (macOS) or `ufw status` (Linux).",
        fix_time_estimate="1 min", location="firewall", confidence="low",
    )


def _check_screen_lock_disabled(manifest, root) -> list:
    if not _home_is_scan_root(manifest):
        return []
    os_name = manifest.host.get("os", "")

    if os_name == "Darwin":
        try:
            proc = subprocess.run(
                ["defaults", "read", "com.apple.screensaver", "askForPassword"],
                capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return [_unknown_screen_lock_finding()]
        value = proc.stdout.strip()
        if proc.returncode != 0 or value == "":
            return [_unknown_screen_lock_finding()]
        if value == "0":
            return [Finding(
                check_id="network.screen_lock_disabled",
                category=CATEGORY, severity=Severity.MEDIUM,
                title="Screen lock does not require a password on wake (best-effort check)",
                evidence=Evidence(detail={"checked_via": "defaults read com.apple.screensaver askForPassword"}),
                fix="System Settings -> Lock Screen -> require password Immediately.",
                fix_time_estimate="2 min", location="screensaver", confidence="medium",
            )]
        return []

    return [_unknown_screen_lock_finding()]  # Linux desktop-env-specific, not implemented in v1


def _unknown_screen_lock_finding() -> Finding:
    return Finding(
        check_id="network.screen_lock_disabled",
        category=CATEGORY, severity=Severity.INFO,
        title="Could not determine screen lock state automatically",
        evidence=Evidence(),
        fix="Check manually: does the screen require a password immediately on wake/lock?",
        fix_time_estimate="1 min", location="screen-lock", confidence="low",
    )


def run(manifest, root, context=None) -> list:
    findings = []
    findings += _check_bound_all_interfaces(manifest, root)
    findings += _check_tunnel_without_access_policy(manifest, root)
    findings += _check_dual_exposure(manifest, root)
    findings += _check_firewall_disabled(manifest, root)
    findings += _check_screen_lock_disabled(manifest, root)
    return findings
