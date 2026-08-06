"""Supply-chain checks. Four checks:
  1. npm_install_lifecycle_hook -- preinstall/postinstall/prepare scripts
     (arbitrary code execution on `npm install`)
  2. dependency_from_git_or_tarball_url -- registry bypassed entirely
  3. forked_dependency_behind_upstream -- local-evidence-only, INFO,
     companion to (2): a git-pinned dependency can't be verified against
     upstream without a network call, so this is a prompt to check
     manually, not a real detector
  4. npm_audit_findings / pip_audit_findings -- OPT-IN ONLY via
     context["allow_audit_tools"], since these make registry calls, the
     one documented exception to this tool's no-outbound-calls default
"""

from __future__ import annotations

import json
import os
import re
import subprocess

from asa.finding import Category, Evidence, Finding, Severity

CATEGORY = Category.SUPPLY_CHAIN
CHECK_IDS = [
    "supply_chain.npm_install_lifecycle_hook",
    "supply_chain.dependency_from_git_or_tarball_url",
    "supply_chain.forked_dependency_behind_upstream",
    "supply_chain.npm_audit_findings",
    "supply_chain.pip_audit_findings",
]

TRIVIAL_SCRIPT = re.compile(r"^\s*(echo\b.*|:|true|#.*)?\s*$", re.IGNORECASE)
GIT_URL_PATTERN = re.compile(r"(git\+(?:https?|ssh)://[^\s\"',]+)")
TARBALL_URL_PATTERN = re.compile(r"(https?://[^\s\"',]+\.(?:tar\.gz|tgz))")

NPM_SEVERITY_MAP = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "moderate": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
}


def activates(manifest) -> bool:
    return manifest.has_kind("node_project") or manifest.has_kind("python_project")


def _check_lifecycle_hooks(manifest, root) -> list:
    findings = []
    for comp in manifest.components_of("node_project"):
        if "package.json" not in comp.signature_files:
            continue
        comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        path = os.path.join(comp_dir, "package.json")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            continue
        for hook in ("preinstall", "postinstall", "prepare"):
            script = scripts.get(hook)
            if not script:
                continue
            trivial = bool(TRIVIAL_SCRIPT.match(script))
            rel = os.path.relpath(path, root) if path.startswith(root) else path
            findings.append(Finding(
                check_id="supply_chain.npm_install_lifecycle_hook",
                category=CATEGORY,
                severity=Severity.LOW if trivial else Severity.HIGH,
                title=f"package.json has a {hook} script -- runs automatically on `npm install`",
                evidence=Evidence(file=rel, variable_name=hook, snippet=script[:160]),
                fix="Confirm this is expected and comes from a trusted source. Install-time hooks are a common supply-chain attack vector.",
                fix_time_estimate="5 min", location=f"{rel}:scripts.{hook}",
                confidence="medium" if trivial else "high",
            ))
    return findings


def _check_git_and_tarball_deps(manifest, root) -> list:
    findings = []
    seen = set()

    def emit(url: str, rel_path: str, kind: str):
        if (url, rel_path) in seen:
            return
        seen.add((url, rel_path))
        findings.append(Finding(
            check_id="supply_chain.dependency_from_git_or_tarball_url",
            category=CATEGORY, severity=Severity.MEDIUM,
            title=f"Dependency sourced from a {kind} instead of the package registry",
            evidence=Evidence(file=rel_path, snippet=url[:200]),
            fix="Prefer a registry release unless there's a specific reason to pin to a git ref/tarball. If there is, document why.",
            fix_time_estimate="10 min", location=rel_path,
        ))
        findings.append(Finding(
            check_id="supply_chain.forked_dependency_behind_upstream",
            category=CATEGORY, severity=Severity.INFO,
            title=f"Git/tarball-sourced dependency can't be checked against upstream without a network call",
            evidence=Evidence(file=rel_path, snippet=url[:200]),
            fix="Manually confirm this ref isn't a long-lived fork that has silently fallen behind upstream security patches.",
            fix_time_estimate="10 min", location=rel_path, confidence="low",
        ))

    for comp in manifest.components_of("node_project"):
        if "package.json" not in comp.signature_files:
            continue
        comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        path = os.path.join(comp_dir, "package.json")
        rel = os.path.relpath(path, root) if path.startswith(root) else path
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            v = data.get(key)
            if isinstance(v, dict):
                deps.update(v)
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            m = GIT_URL_PATTERN.search(spec) or TARBALL_URL_PATTERN.search(spec)
            if m:
                emit(m.group(1), rel, "git URL" if spec.startswith("git+") else "tarball URL")

    for comp in manifest.components_of("python_project"):
        for fname in comp.signature_files:
            if fname not in ("requirements.txt", "Pipfile"):
                continue
            comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
            path = os.path.join(comp_dir, fname)
            rel = os.path.relpath(path, root) if path.startswith(root) else path
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue
            for m in GIT_URL_PATTERN.finditer(content):
                emit(m.group(1), rel, "git URL")
            for m in TARBALL_URL_PATTERN.finditer(content):
                emit(m.group(1), rel, "tarball URL")

        if "pyproject.toml" in comp.signature_files:
            comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
            path = os.path.join(comp_dir, "pyproject.toml")
            rel = os.path.relpath(path, root) if path.startswith(root) else path
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue
            for m in GIT_URL_PATTERN.finditer(content):
                emit(m.group(1), rel, "git URL")
    return findings


def _run_npm_audit(manifest, root) -> list:
    findings = []
    for comp in manifest.components_of("node_project"):
        comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        rel = os.path.relpath(comp_dir, root) if comp_dir.startswith(root) else comp_dir
        try:
            proc = subprocess.run(
                ["npm", "audit", "--json"], cwd=comp_dir,
                capture_output=True, text=True, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        try:
            data = json.loads(proc.stdout or "{}")
        except ValueError:
            continue
        vulns = data.get("vulnerabilities", {})
        for pkg_name, info in vulns.items():
            severity = NPM_SEVERITY_MAP.get(info.get("severity", "info"), Severity.INFO)
            findings.append(Finding(
                check_id="supply_chain.npm_audit_findings",
                category=CATEGORY, severity=severity,
                title=f"npm audit: {pkg_name} has a {info.get('severity', 'unknown')}-severity advisory",
                evidence=Evidence(file=rel, variable_name=pkg_name),
                fix=f"Run `npm audit fix` cautiously (review the diff) in {rel}, or update {pkg_name} manually.",
                fix_time_estimate="varies", location=f"{rel} ({pkg_name})",
            ))
    return findings


def _run_pip_audit(manifest, root) -> list:
    findings = []
    for comp in manifest.components_of("python_project"):
        comp_dir = comp.root if os.path.isabs(comp.root) else os.path.join(root, comp.root)
        rel = os.path.relpath(comp_dir, root) if comp_dir.startswith(root) else comp_dir
        try:
            proc = subprocess.run(
                ["pip-audit", "-f", "json"], cwd=comp_dir,
                capture_output=True, text=True, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        try:
            data = json.loads(proc.stdout or "[]")
        except ValueError:
            continue
        deps = data if isinstance(data, list) else data.get("dependencies", [])
        for dep in deps:
            for vuln in dep.get("vulns", []):
                findings.append(Finding(
                    check_id="supply_chain.pip_audit_findings",
                    category=CATEGORY, severity=Severity.MEDIUM,
                    title=f"pip-audit: {dep.get('name')} has advisory {vuln.get('id', 'unknown')}",
                    evidence=Evidence(file=rel, variable_name=dep.get("name")),
                    fix=f"Upgrade {dep.get('name')} to one of: {', '.join(vuln.get('fix_versions', []) or ['see advisory'])}",
                    fix_time_estimate="varies", location=f"{rel} ({dep.get('name')})",
                ))
    return findings


def run(manifest, root, context=None) -> list:
    context = context or {}
    findings = []
    findings += _check_lifecycle_hooks(manifest, root)
    findings += _check_git_and_tarball_deps(manifest, root)
    if context.get("allow_audit_tools"):
        findings += _run_npm_audit(manifest, root)
        findings += _run_pip_audit(manifest, root)
    return findings
