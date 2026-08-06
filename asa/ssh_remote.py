"""Remote-over-SSH execution: a single self-contained script, generated at
scan time from THIS process's own loaded modules (guarantees exact version
match -- no separate bundle artifact to drift out of sync), piped to
`ssh <host> python3 -`. No pre-install required on the remote box beyond a
plain python3 -- matches "run this against a stranger's box you already
have SSH access to" without adding a package-manager dependency.

Remote mode deliberately excludes: --ai (the bundle never includes
ai_assist.py), asa/fixer.py (scan-only over SSH in v1 -- no mutating a
remote filesystem from here), and any check needing live desktop-session
state (skipped there with an explicit reason, same as locally).

The remote driver prints exactly ONE line of compact JSON as the LAST line
of stdout -- diagnostics/progress go to stderr. Local side scans stdout
from the end for the first line that parses as JSON with the expected
top-level keys, so an SSH login banner or MOTD ahead of it doesn't break
parsing.
"""

from __future__ import annotations

import inspect
import json
import subprocess

import asa.checkers.agent_blast_radius
import asa.checkers.base
import asa.checkers.ci_injection
import asa.checkers.network
import asa.checkers.permissions
import asa.checkers.secrets
import asa.checkers.supply_chain
import asa.data.secret_patterns
import asa.data.signatures
import asa.finding
import asa.manifest
import asa.redact
import asa.registry
import asa.runner
from asa import __version__

# Dependency order matters -- a module's `from asa.X import Y` line only
# resolves correctly if asa.X was already loaded (and registered in the
# remote process's sys.modules) earlier in this list. Split into two
# phases around asa.registry specifically: registry's own source does
# `from asa.checkers import CHECKER_MODULES`, which must already exist as
# an attribute on the (fake, bundle-only) asa.checkers package BEFORE
# registry's source executes -- not after, which is what a single flat
# list would give if CHECKER_MODULES were only assembled in the footer.
_PRE_REGISTRY_MODULES = [
    asa.finding,
    asa.data.secret_patterns,
    asa.data.signatures,
    asa.redact,
    asa.manifest,
    asa.checkers.base,
    asa.checkers.secrets,
    asa.checkers.permissions,
    asa.checkers.network,
    asa.checkers.ci_injection,
    asa.checkers.supply_chain,
    asa.checkers.agent_blast_radius,
]
_POST_REGISTRY_MODULES = [
    asa.registry,
    asa.runner,
]
_BUNDLE_MODULES = _PRE_REGISTRY_MODULES + _POST_REGISTRY_MODULES  # for tests that just want "everything"

_BOOTSTRAP = '''\
import sys, types
def _asa_bundle_exec(name, src):
    mod = sys.modules.get(name) or types.ModuleType(name)
    mod.__dict__["__name__"] = name
    mod.__package__ = name if name == "asa" else name.rsplit(".", 1)[0]
    sys.modules[name] = mod
    exec(compile(src, name, "exec"), mod.__dict__)
    if "." in name:
        parent, attr = name.rsplit(".", 1)
        if parent in sys.modules:
            setattr(sys.modules[parent], attr, mod)
    return mod

for _pkg in ("asa", "asa.data", "asa.checkers"):
    if _pkg not in sys.modules:
        _m = types.ModuleType(_pkg)
        _m.__package__ = _pkg
        sys.modules[_pkg] = _m
        if "." in _pkg:
            _parent, _attr = _pkg.rsplit(".", 1)
            setattr(sys.modules[_parent], _attr, _m)
'''

_SET_CHECKER_MODULES = '''\
sys.modules["asa.checkers"].CHECKER_MODULES = [
    sys.modules["asa.checkers.secrets"],
    sys.modules["asa.checkers.permissions"],
    sys.modules["asa.checkers.network"],
    sys.modules["asa.checkers.ci_injection"],
    sys.modules["asa.checkers.supply_chain"],
    sys.modules["asa.checkers.agent_blast_radius"],
]
for _m in sys.modules["asa.checkers"].CHECKER_MODULES:
    sys.modules["asa.checkers.base"].validate_checker_module(_m)
'''

_DRIVER_FOOTER = '''\
import json as _json

_req = _json.loads(sys.argv[1])
_manifest, _findings, _coverage = sys.modules["asa.runner"].run(
    _req["scan_root"],
    scope=_req.get("scope", "project"),
    include_vendored=_req.get("include_vendored", False),
    categories=_req.get("categories"),
    context=_req.get("context") or {},
    is_remote=True,
)

_dotenv_mod = sys.modules["asa.checkers.secrets"]
_modes = {}
import os as _os
for _p in _dotenv_mod.dotenv_paths(_manifest, _manifest.scan_root):
    try:
        _modes[_p] = _os.stat(_p).st_mode & 0o777
    except OSError:
        pass

_payload = {
    "manifest": _manifest.to_dict(),
    "findings": [_f.to_dict() for _f in _findings],
    "coverage": _coverage,
    "dotenv_modes": _modes,
    "tool_version": "__ASA_TOOL_VERSION__",
}
print(_json.dumps(_payload, separators=(",", ":")))
'''


def _exec_calls(modules) -> list:
    return [f"_asa_bundle_exec({mod.__name__!r}, {inspect.getsource(mod)!r})\n" for mod in modules]


def build_bundle_script() -> str:
    """Flattens this process's own currently-loaded asa modules into one
    script. Each module's ORIGINAL source is preserved verbatim (imports
    included) -- correctness comes from pre-seeding sys.modules in
    dependency order, not from rewriting import statements."""
    parts = [_BOOTSTRAP]
    parts.extend(_exec_calls(_PRE_REGISTRY_MODULES))
    parts.append(_SET_CHECKER_MODULES)
    parts.extend(_exec_calls(_POST_REGISTRY_MODULES))
    parts.append(_DRIVER_FOOTER.replace("__ASA_TOOL_VERSION__", __version__))
    return "\n".join(parts)


def _extract_json_line(stdout: str) -> dict:
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if "manifest" in data and "findings" in data and "coverage" in data:
            return data
    raise RuntimeError("could not find a valid scan JSON line in remote output")


def run(host: str, *, scan_root: str = "~", scope: str = "project", include_vendored: bool = False,
        categories: list = None, context: dict = None, timeout: int = 300):
    """Runs a scan on `host` over SSH. Returns (manifest, findings,
    coverage) via the same reconstruction path as a local saved scan.
    Raises RuntimeError with the remote stderr on any failure -- never
    silently returns an empty/partial result."""
    from asa.serialize import scan_data_to_objects

    script = build_bundle_script()
    request = json.dumps({
        "scan_root": scan_root, "scope": scope, "include_vendored": include_vendored,
        "categories": categories, "context": context or {},
    })

    try:
        proc = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR", host, "python3", "-", request],
            input=script, capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"ssh not found locally: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"remote scan on {host} timed out after {timeout}s") from exc

    if proc.returncode != 0:
        raise RuntimeError(f"remote scan on {host} failed (exit {proc.returncode}): {proc.stderr.strip()[:2000]}")

    data = _extract_json_line(proc.stdout)
    manifest, findings, coverage = scan_data_to_objects(data)

    for f in findings:
        f.location = f"{host}:{f.location}"

    return manifest, findings, coverage
