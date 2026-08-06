"""File/OS permission checks. Five checks:
  1. ssh_private_key_no_passphrase -- key opens with no passphrase at all
  2. ssh_private_key_permissive_mode -- key file mode looser than 0600
  3. sensitive_file_world_readable -- other credential-shaped files (.pem,
     .key, cloud CLI config dirs) readable by group/other
  4. home_directory_too_permissive -- home dir mode looser than 0750
  5. insecure_default_umask -- umask weaker than 0077/0027 in shell rc
     files, or absent entirely (flagged INFO, not assumed safe)
"""

from __future__ import annotations

import os
import re
import subprocess

from asa.finding import Category, Evidence, Finding, Severity

CATEGORY = Category.PERMISSIONS
CHECK_IDS = [
    "permissions.ssh_private_key_no_passphrase",
    "permissions.ssh_private_key_permissive_mode",
    "permissions.sensitive_file_world_readable",
    "permissions.home_directory_too_permissive",
    "permissions.insecure_default_umask",
]

SENSITIVE_EXTENSIONS = {".pem", ".key"}
SENSITIVE_FILENAME_PATTERNS = [
    re.compile(r"^id_(rsa|dsa|ecdsa|ed25519)$"),
    re.compile(r"^credentials$"),  # ~/.aws/credentials
]
CLOUD_CONFIG_DIRS = {".aws", ".gcloud", ".config/gcloud", ".azure"}

UMASK_LINE = re.compile(r"^\s*umask\s+(\d{3,4})\s*$", re.MULTILINE)
RC_FILES = (".bashrc", ".zshrc", ".profile", ".bash_profile")


def activates(manifest) -> bool:
    return manifest.has_kind("ssh_dir") or _home_is_scan_root(manifest)


def _home_is_scan_root(manifest) -> bool:
    home = os.path.expanduser("~")
    try:
        return os.path.realpath(manifest.scan_root) == os.path.realpath(home)
    except OSError:
        return False


def _is_private_key_file(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
    except OSError:
        return False
    return b"PRIVATE KEY" in head


def _has_passphrase(path: str):
    """Returns True (protected), False (no passphrase), or None (could not
    determine -- ssh-keygen missing, or not actually a valid key)."""
    try:
        proc = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", path],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode == 0:
        return False
    stderr = proc.stderr.lower()
    if "incorrect passphrase" in stderr or "pass phrase" in stderr:
        return True
    return None


def _iter_ssh_key_files(ssh_dir: str):
    try:
        entries = os.listdir(ssh_dir)
    except OSError:
        return
    for name in entries:
        if name.endswith(".pub") or name in ("known_hosts", "known_hosts.old", "config", "authorized_keys"):
            continue
        path = os.path.join(ssh_dir, name)
        if os.path.isfile(path) and _is_private_key_file(path):
            yield path


def _check_ssh_keys(manifest, root) -> list:
    findings = []
    for comp in manifest.components_of("ssh_dir"):
        ssh_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        ssh_dir = os.path.normpath(ssh_dir)
        for key_path in _iter_ssh_key_files(ssh_dir):
            try:
                mode = os.stat(key_path).st_mode & 0o777
            except OSError:
                continue
            if mode & 0o077:
                findings.append(Finding(
                    check_id="permissions.ssh_private_key_permissive_mode",
                    category=CATEGORY, severity=Severity.HIGH,
                    title=f"SSH private key {os.path.basename(key_path)} is readable by users other than its owner",
                    evidence=Evidence(file=key_path, detail={"mode": oct(mode), "expected": "0600"}),
                    fix=f"chmod 600 {key_path}",
                    fix_time_estimate="1 min", location=key_path, auto_fixable=True,
                ))

            has_pass = _has_passphrase(key_path)
            if has_pass is False:
                findings.append(Finding(
                    check_id="permissions.ssh_private_key_no_passphrase",
                    category=CATEGORY, severity=Severity.HIGH,
                    title=f"SSH private key {os.path.basename(key_path)} has no passphrase",
                    evidence=Evidence(file=key_path),
                    fix=(
                        f"Add UseKeychain yes to ~/.ssh/config, then `ssh-keygen -p -f {key_path}` to set a "
                        f"passphrase, then `ssh-add --apple-use-keychain {key_path}` (macOS) so you aren't "
                        f"retyping it. Check first whether anything unattended (cron, CI) depends on this key "
                        f"working without a prompt."
                    ),
                    fix_time_estimate="10 min", location=key_path,
                ))
    return findings


def _check_sensitive_files_world_readable(manifest, root) -> list:
    findings = []
    for comp in manifest.components_of("ssh_dir"):
        ssh_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        try:
            entries = os.listdir(ssh_dir)
        except OSError:
            entries = []
        for name in entries:
            path = os.path.join(ssh_dir, name)
            if name == "config" and os.path.isfile(path):
                try:
                    mode = os.stat(path).st_mode & 0o777
                except OSError:
                    continue
                if mode & 0o077:
                    findings.append(_world_readable_finding(path, "SSH config file"))

    home = os.path.expanduser("~")
    if _home_is_scan_root(manifest):
        for cloud_dir in CLOUD_CONFIG_DIRS:
            full = os.path.join(home, cloud_dir)
            if not os.path.isdir(full):
                continue
            for name in ("credentials", "config"):
                path = os.path.join(full, name)
                if os.path.isfile(path):
                    try:
                        mode = os.stat(path).st_mode & 0o777
                    except OSError:
                        continue
                    if mode & 0o077:
                        findings.append(_world_readable_finding(path, f"{cloud_dir}/{name}"))
    return findings


def _world_readable_finding(path: str, label: str) -> Finding:
    mode = os.stat(path).st_mode & 0o777
    return Finding(
        check_id="permissions.sensitive_file_world_readable",
        category=CATEGORY, severity=Severity.HIGH,
        title=f"{label} is readable by users other than its owner",
        evidence=Evidence(file=path, detail={"mode": oct(mode), "expected": "0600"}),
        fix=f"chmod 600 {path}",
        fix_time_estimate="1 min", location=path, auto_fixable=True,
    )


def _check_home_directory_permissive(manifest, root) -> list:
    if not _home_is_scan_root(manifest):
        return []
    home = os.path.expanduser("~")
    try:
        mode = os.stat(home).st_mode & 0o777
    except OSError:
        return []
    if mode & 0o027:  # group or other has more than execute/traverse
        return [Finding(
            check_id="permissions.home_directory_too_permissive",
            category=CATEGORY, severity=Severity.MEDIUM,
            title="Home directory permissions are looser than 0750",
            evidence=Evidence(file=home, detail={"mode": oct(mode), "expected": "0750 or tighter"}),
            fix=f"chmod 750 {home} -- confirm nothing else on the box depends on wider access first.",
            fix_time_estimate="5 min", location=home,
        )]
    return []


def _check_umask(manifest, root) -> list:
    if not _home_is_scan_root(manifest):
        return []
    home = os.path.expanduser("~")
    findings = []
    found_any_setting = False
    for rc in RC_FILES:
        path = os.path.join(home, rc)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        m = UMASK_LINE.search(content)
        if m:
            found_any_setting = True
            value = m.group(1)
            numeric = int(value, 8)
            if (numeric & 0o077) < 0o077:  # weaker than 077 means some group/other access granted
                findings.append(Finding(
                    check_id="permissions.insecure_default_umask",
                    category=CATEGORY, severity=Severity.LOW,
                    title=f"Default umask in {rc} ({value}) allows group/other access to new files",
                    evidence=Evidence(file=path, detail={"umask": value, "recommended": "077 or 027"}),
                    fix=f"Set `umask 077` in {path} for new files to default to owner-only.",
                    fix_time_estimate="2 min", location=path,
                ))
    if not found_any_setting:
        findings.append(Finding(
            check_id="permissions.insecure_default_umask",
            category=CATEGORY, severity=Severity.INFO,
            title="No explicit umask setting found in shell startup files",
            evidence=Evidence(detail={"checked": list(RC_FILES)}),
            fix="Not necessarily a problem -- the OS default may already be reasonable. Confirm with `umask` in a fresh shell.",
            fix_time_estimate="1 min", location=home, confidence="medium",
        ))
    return findings


def run(manifest, root, context=None) -> list:
    findings = []
    findings += _check_ssh_keys(manifest, root)
    findings += _check_sensitive_files_world_readable(manifest, root)
    findings += _check_home_directory_permissive(manifest, root)
    findings += _check_umask(manifest, root)
    return findings
