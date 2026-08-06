"""Black-box, full-pipeline leakage check. Plants several distinctly-shaped
secrets in a synthetic project, runs manifest -> checkers -> report model
-> every renderer (term, md, html) -> JSON, and asserts the literal secret
values -- and every >=4-char substring of each -- appear nowhere in any of
that output.

This is the single most important test in the suite: it operationalizes
"prove masking actually masks on real sample data" rather than trusting
that redact.py's regex looks correct. It's the same shape of test that
would have caught the real incident this tool's design is built around (a
masking regex silently no-op'ing under BSD sed on macOS) -- except here the
check is behavioral and platform-agnostic by construction.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest

from asa import runner
from asa.report.html import render_html
from asa.report.model import build_report_model
from asa.report.text import render_text

PLANTED_SECRETS = {
    "google_api_key": "AIza" + "Xy9" * 12,
    "github_pat": "ghp_" + "aB3dE7" * 6,
    # random-looking on purpose -- an earlier version of this fixture used
    # a word-built password ("hunter2ThisIsNotARealPassword...") and the
    # test failed on real report prose ("una[unte]d" inside "unaccounted"
    # collided with a 4-char window of the secret). That's a fixture bug,
    # not a masking bug: any 4-char substring of a secret built from common
    # English word fragments is likely to recur in ordinary English text by
    # chance. Random values sidestep the ambiguity entirely.
    "generic_password": "Qx7mVz2LpNw9RtKfDh4Bc6",
    # deliberately contains regex metacharacters -- proves masking doesn't
    # depend on the value being regex-safe
    "weird_chars_password": "Zt#4.Kq*1Wp$8(Yn)3[Xr]7",
}


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def build_fixture(root: str) -> None:
    write(os.path.join(root, "config.yaml"), f"PASSWORD: {PLANTED_SECRETS['generic_password']}\n")
    write(os.path.join(root, "other_config.yaml"), f"SECRET_TOKEN: {PLANTED_SECRETS['weird_chars_password']}\n")
    write(os.path.join(root, "app.py"), f'GOOGLE_KEY = "{PLANTED_SECRETS["google_api_key"]}"\n')
    write(os.path.join(root, "deploy.sh"), f'export GITHUB_TOKEN={PLANTED_SECRETS["github_pat"]}\n')

    env_path = os.path.join(root, ".env")
    write(env_path, f"PASSWORD={PLANTED_SECRETS['generic_password']}\n")
    os.chmod(env_path, 0o644)  # trips the world-readable check too

    write(os.path.join(root, "sub", ".env"), f"PASSWORD={PLANTED_SECRETS['generic_password']}\n")  # collision + duplicate-value trigger


def build_git_history_fixture(root: str) -> None:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.com",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.com"}

    def git(*args):
        subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, env=env)

    git("init", "-q")
    secret_path = os.path.join(root, "old_creds.pem")
    write(secret_path, f"KEY={PLANTED_SECRETS['google_api_key']}\n")
    git("add", "old_creds.pem")
    git("commit", "-q", "-m", "oops committed a key")
    os.remove(secret_path)
    git("add", "-A")
    git("commit", "-q", "-m", "remove it")


def _all_substrings_4plus(value: str):
    for i in range(len(value) - 3):
        yield value[i : i + 4]


@unittest.skipIf(subprocess.run(["which", "git"], capture_output=True).returncode != 0, "git not installed")
class TestNoSecretLeakageFullPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        build_fixture(self.root)
        build_git_history_fixture(self.root)

        self.manifest, self.findings, self.coverage = runner.run(self.root)
        self.assertGreater(len(self.findings), 0, "fixture must actually produce findings for this test to be meaningful")
        self.model = build_report_model(self.manifest, self.findings, self.coverage)

    def tearDown(self):
        self.tmp.cleanup()

    def _assert_clean(self, blob: str, where: str):
        for name, secret in PLANTED_SECRETS.items():
            self.assertNotIn(secret, blob, f"planted secret {name!r} leaked verbatim into {where}")
            for sub in _all_substrings_4plus(secret):
                self.assertNotIn(sub, blob, f"substring {sub!r} of planted secret {name!r} leaked into {where}")

    def test_terminal_output_clean(self):
        out = render_text(self.model, fmt="term", verbose=True)
        self._assert_clean(out, "terminal report (verbose)")

    def test_markdown_output_clean(self):
        out = render_text(self.model, fmt="md")
        self._assert_clean(out, "markdown report")

    def test_html_output_clean(self):
        out = render_html(self.model)
        self._assert_clean(out, "HTML report")

    def test_json_output_clean(self):
        blob = json.dumps([f.to_dict() for f in self.findings])
        self._assert_clean(blob, "JSON finding dump")

    def test_finding_repr_clean(self):
        # covers anything that might repr() a Finding during debugging/logging
        blob = "\n".join(repr(f) for f in self.findings)
        self._assert_clean(blob, "Finding repr()")

    def test_manifest_output_clean(self):
        blob = json.dumps(self.manifest.to_dict())
        self._assert_clean(blob, "manifest JSON")


if __name__ == "__main__":
    unittest.main()
