"""Declarative stack/signature detection table. Each Signature pairs a
component `kind` with a small matcher function that looks at one directory
at a time (its direct filenames/dirnames) and returns the marker files that
matched, or None. Adding support for a new stack shape means writing one
matcher function and adding one entry to SIGNATURES below -- nothing else
in the detection engine needs to change.

Two classes of signature:
  - project-level: detected by walking the scan target (node/python/docker/
    k8s/github-actions/ssh/claude-code/mcp/dotenv).
  - machine-level: detected by checking fixed, well-known OS paths rather
    than walking (systemd units, cron files, a Hermes install) -- only
    checked when scanning with --scope machine.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Callable, Optional

Matcher = Callable[[str, list, list], Optional[list]]


@dataclass(frozen=True)
class Signature:
    kind: str
    matcher: Matcher
    description: str = ""


def _match_node_project(dirpath, filenames, dirnames):
    if "package.json" in filenames:
        return ["package.json"]
    return None


def _match_python_project(dirpath, filenames, dirnames):
    hits = [f for f in ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile") if f in filenames]
    return hits or None


def _match_docker_compose(dirpath, filenames, dirnames):
    hits = [f for f in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml") if f in filenames]
    return hits or None


def _match_dockerfile(dirpath, filenames, dirnames):
    if "Dockerfile" in filenames:
        return ["Dockerfile"]
    return None


def _match_github_actions(dirpath, filenames, dirnames):
    if os.path.basename(dirpath) == "workflows" and os.path.basename(os.path.dirname(dirpath)) == ".github":
        hits = [f for f in filenames if f.endswith((".yml", ".yaml"))]
        return hits or None
    return None


def _match_ssh_dir(dirpath, filenames, dirnames):
    if os.path.basename(dirpath) == ".ssh":
        return ["<directory>"]
    return None


def _match_cloudflared_config(dirpath, filenames, dirnames):
    if os.path.basename(dirpath) == ".cloudflared":
        hits = [f for f in filenames if f.endswith((".yml", ".yaml"))]
        return hits or None
    return None


def _match_hermes_profile(dirpath, filenames, dirnames):
    if os.path.basename(dirpath) == ".hermes":
        return ["<directory>"]
    return None


def _match_claude_code_config(dirpath, filenames, dirnames):
    if os.path.basename(dirpath) == ".claude" and "settings.json" in filenames:
        return ["settings.json"]
    if ".mcp.json" in filenames:
        return [".mcp.json"]
    return None


def _probe_mcp_servers_key(filepath: str) -> bool:
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and "mcpServers" in data


def _match_mcp_config(dirpath, filenames, dirnames):
    if "claude_desktop_config.json" in filenames:
        return ["claude_desktop_config.json"]
    return None


def _match_dotenv_files(dirpath, filenames, dirnames):
    hits = [f for f in filenames if f == ".env" or f.startswith(".env.")]
    return hits or None


_K8S_CONTENT_PROBE = re.compile(r"^apiVersion:\s*\S+", re.MULTILINE)
_K8S_KIND_PROBE = re.compile(r"^kind:\s*(Deployment|Service|Pod|ConfigMap|Secret|Ingress|StatefulSet|DaemonSet|Job|CronJob)\b", re.MULTILINE)


def _looks_like_k8s_manifest(filepath: str) -> bool:
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    return bool(_K8S_CONTENT_PROBE.search(head) and _K8S_KIND_PROBE.search(head))


def _match_k8s_manifests(dirpath, filenames, dirnames):
    hits = []
    for f in filenames:
        if f.endswith((".yml", ".yaml")) and f not in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            if _looks_like_k8s_manifest(os.path.join(dirpath, f)):
                hits.append(f)
    return hits or None


# Project-level signatures, checked once per directory during the walk.
SIGNATURES: list[Signature] = [
    Signature("node_project", _match_node_project, "package.json present"),
    Signature("python_project", _match_python_project, "requirements.txt / pyproject.toml / setup.py / Pipfile present"),
    Signature("docker_compose", _match_docker_compose, "docker-compose.yml / compose.yml present"),
    Signature("dockerfile", _match_dockerfile, "Dockerfile present"),
    Signature("github_actions", _match_github_actions, ".github/workflows/*.yml present"),
    Signature("ssh_dir", _match_ssh_dir, ".ssh directory present"),
    Signature("cloudflared_config", _match_cloudflared_config, ".cloudflared/*.yml present"),
    Signature("hermes_profile", _match_hermes_profile, ".hermes directory present"),
    Signature("claude_code_config", _match_claude_code_config, ".claude/settings.json or .mcp.json present"),
    Signature("mcp_config", _match_mcp_config, "claude_desktop_config.json present"),
    Signature("dotenv_files", _match_dotenv_files, ".env* file present"),
    Signature("k8s_manifests", _match_k8s_manifests, "YAML file with apiVersion+kind present"),
]

# Directory names excluded from the walk by default (recorded into
# Manifest.skipped with a reason, not silently dropped).
VENDORED_DIR_NAMES = {
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "egg-info", ".egg-info",
}


# --- machine-level signatures: fixed, well-known paths, not tree-walked ---

def detect_machine_signatures(home_dir: str) -> list[tuple]:
    """Returns (kind, root_path, marker) tuples for machine-level
    components that live at fixed OS conventions rather than under an
    arbitrary project directory. Only called when scope == "machine"."""
    hits = []

    hermes_dir = os.path.join(home_dir, ".hermes")
    if os.path.isdir(hermes_dir):
        hits.append(("hermes_profile", hermes_dir, "~/.hermes directory present"))

    for cron_path in ("/etc/crontab",):
        if os.path.isfile(cron_path):
            hits.append(("cron_files", cron_path, "/etc/crontab present"))
    cron_d = "/etc/cron.d"
    if os.path.isdir(cron_d):
        try:
            if os.listdir(cron_d):
                hits.append(("cron_files", cron_d, "/etc/cron.d present with entries"))
        except OSError:
            pass

    systemd_dir = "/etc/systemd/system"
    if os.path.isdir(systemd_dir):
        try:
            units = [f for f in os.listdir(systemd_dir) if f.endswith(".service")]
            if units:
                hits.append(("systemd_units", systemd_dir, f"{len(units)} .service unit(s) present"))
        except OSError:
            pass

    return hits
