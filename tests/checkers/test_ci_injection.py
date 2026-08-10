import os
import tempfile
import unittest

from asa import manifest as manifest_mod
from asa.checkers import ci_injection as ci_checker


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def run_ci(root, context=None):
    m = manifest_mod.build(root)
    return ci_checker.run(m, root, context)


class TestActivation(unittest.TestCase):
    def test_does_not_activate_without_workflows(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), "{}")
            m = manifest_mod.build(root)
            self.assertFalse(ci_checker.activates(m))

    def test_activates_with_workflow(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "ci.yml"), "on: push\njobs: {}\n")
            m = manifest_mod.build(root)
            self.assertTrue(ci_checker.activates(m))


REAL_VULNERABLE_WORKFLOW = """\
name: Insert upcoming draw (manual)

on:
  workflow_dispatch:
    inputs:
      draw_number:
        required: true
        type: string

jobs:
  insert:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Insert upcoming draw
        uses: actions/github-script@v7
        env:
          SUPABASE_DATA_SERVICE_ROLE_KEY: ${{ secrets.SUPABASE_DATA_SERVICE_ROLE_KEY }}
        with:
          script: |
            const supabase = createClient(url, key);
            const { error } = await supabase.from('upcoming_draw').upsert({
              draw_number: Number('${{ github.event.inputs.draw_number }}'),
            });
"""

REAL_FIXED_WORKFLOW = """\
name: Insert upcoming draw (manual)

on:
  workflow_dispatch:
    inputs:
      draw_number:
        required: true
        type: string

jobs:
  insert:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      - name: Insert upcoming draw
        uses: actions/github-script@v7
        env:
          SUPABASE_DATA_SERVICE_ROLE_KEY: ${{ secrets.SUPABASE_DATA_SERVICE_ROLE_KEY }}
          DRAW_NUMBER: ${{ github.event.inputs.draw_number }}
        with:
          script: |
            const supabase = createClient(url, key);
            const { error } = await supabase.from('upcoming_draw').upsert({
              draw_number: Number(process.env.DRAW_NUMBER),
            });
"""


class TestRealWorldFixture(unittest.TestCase):
    """Ground-truthed against the actual toto-backend vulnerability fixed
    during the real audit this tool is built from."""

    def test_vulnerable_version_flags_injection_and_escalates(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "insert-upcoming-draw.yml"), REAL_VULNERABLE_WORKFLOW)
            findings = run_ci(root)
            ids = [f.check_id for f in findings]
            self.assertIn("ci.injection_with_high_privilege_secret_in_scope", ids)
            escalated = [f for f in findings if f.check_id == "ci.injection_with_high_privilege_secret_in_scope"]
            self.assertEqual(escalated[0].severity.value, "critical")
            # the plain (non-escalated) github_script finding should NOT
            # also appear once escalated -- one finding, not two for the
            # same root cause
            self.assertNotIn("ci.script_injection_in_github_script", ids)

    def test_fixed_version_has_no_injection_findings(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "insert-upcoming-draw.yml"), REAL_FIXED_WORKFLOW)
            findings = run_ci(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("ci.script_injection_in_github_script", ids)
            self.assertNotIn("ci.injection_with_high_privilege_secret_in_scope", ids)
            # the checkout step is SHA-pinned in this fixture, but
            # actions/github-script@v7 deliberately isn't (the real fix
            # only addressed the injection pattern, not every action's
            # pin) -- so exactly one pin finding, for github-script, not
            # for checkout.
            pin_hits = [f for f in findings if f.check_id == "ci.action_pinned_by_mutable_tag"]
            self.assertEqual(len(pin_hits), 1)
            self.assertIn("github-script", pin_hits[0].evidence.detail["action"])


class TestRunBlockInjection(unittest.TestCase):
    def test_flags_inline_shell_interpolation(self):
        wf = 'on:\n  workflow_dispatch:\n    inputs:\n      x:\n        type: string\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npx tsx x.ts "${{ github.event.inputs.x }}"\n'
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "w.yml"), wf)
            findings = run_ci(root)
            ids = [f.check_id for f in findings]
            self.assertIn("ci.script_injection_in_run_block", ids)

    def test_does_not_flag_env_based_reference(self):
        wf = (
            'on:\n  workflow_dispatch:\n    inputs:\n      x:\n        type: string\n'
            'jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n'
            '      - run: npx tsx x.ts "$X"\n        env:\n          X: ${{ github.event.inputs.x }}\n'
        )
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "w.yml"), wf)
            findings = run_ci(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("ci.script_injection_in_run_block", ids)

    def test_flags_multiline_run_block(self):
        wf = (
            'on:\n  workflow_dispatch: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n'
            '      - run: |\n          echo hello\n          echo "${{ github.event.head_commit.message }}"\n'
        )
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "w.yml"), wf)
            findings = run_ci(root)
            ids = [f.check_id for f in findings]
            self.assertIn("ci.script_injection_in_run_block", ids)


class TestPullRequestTarget(unittest.TestCase):
    def test_flags_untrusted_checkout(self):
        wf = (
            "on:\n  pull_request_target:\n    types: [opened]\n"
            "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        )
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "w.yml"), wf)
            findings = run_ci(root)
            ids = [f.check_id for f in findings]
            self.assertIn("ci.pull_request_target_with_untrusted_checkout", ids)

    def test_plain_pull_request_not_flagged(self):
        wf = (
            "on:\n  pull_request:\n    types: [opened]\n"
            "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "w.yml"), wf)
            findings = run_ci(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("ci.pull_request_target_with_untrusted_checkout", ids)


class TestPinnedByTag(unittest.TestCase):
    def test_flags_tag_pin(self):
        wf = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "w.yml"), wf)
            findings = run_ci(root)
            hits = [f for f in findings if f.check_id == "ci.action_pinned_by_mutable_tag"]
            self.assertEqual(len(hits), 1)

    def test_does_not_flag_sha_pin(self):
        wf = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + "\n"
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "w.yml"), wf)
            findings = run_ci(root)
            hits = [f for f in findings if f.check_id == "ci.action_pinned_by_mutable_tag"]
            self.assertEqual(hits, [])


class TestPermissionsBlock(unittest.TestCase):
    def test_flags_write_all(self):
        wf = "on: push\npermissions: write-all\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []\n"
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "w.yml"), wf)
            findings = run_ci(root)
            hits = [f for f in findings if f.check_id == "ci.overly_broad_github_token_permissions"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].severity.value, "medium")

    def test_flags_missing_permissions_at_low_severity(self):
        wf = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []\n"
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "w.yml"), wf)
            findings = run_ci(root)
            hits = [f for f in findings if f.check_id == "ci.overly_broad_github_token_permissions"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].severity.value, "low")

    def test_explicit_scoped_permissions_not_flagged(self):
        wf = "on: push\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []\n"
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "w.yml"), wf)
            findings = run_ci(root)
            hits = [f for f in findings if f.check_id == "ci.overly_broad_github_token_permissions"]
            self.assertEqual(hits, [])


class TestCleanNoFalsePositives(unittest.TestCase):
    def test_clean_workflow_zero_findings(self):
        wf = (
            "on:\n  push:\n    branches: [main]\n"
            "permissions:\n  contents: read\n"
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@" + "a" * 40 + "\n"
            "      - run: npm test\n"
        )
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "test.yml"), wf)
            findings = run_ci(root)
            self.assertEqual(findings, [])


def _workflow_with_secret(secret_name):
    """Minimal injectable workflow with one named secret in scope. The
    injection itself is constant, so the only variable is whether the
    secret name escalates it to critical."""
    return (
        "on: workflow_dispatch\n"
        "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo \"${{ github.event.inputs.x }}\"\n"
        f"        env:\n          TOKEN: ${{{{ secrets.{secret_name} }}}}\n"
    )


class TestHighPrivilegeSecretList(unittest.TestCase):
    """The escalate-to-critical list is documented in PLAYBOOK.md and in the
    security-audit skill, and is deliberately exhaustive. It drifted once:
    the docs broadened it while the regex kept two vendor-specific whole-name
    literals, so SSH_PRIVATE_KEY and DEPLOY_KEY in an injectable workflow were
    reported High instead of Critical. These cases pin each documented term to
    a concrete secret name."""

    ESCALATES = [
        "SUPABASE_SERVICE_ROLE_KEY",  # via service_role
        "AWS_SECRET_ACCESS_KEY",      # via aws_secret
        "AWS_SECRET_KEY",             # via aws_secret -- missed by the old literal
        "SSH_PRIVATE_KEY",            # via private_key -- previously missed
        "DEPLOY_KEY",                 # via deploy     -- previously missed
        "GH_WRITE_TOKEN",             # via write      -- previously missed
        "ADMIN_TOKEN",
        "ROOT_PASSWORD",
        "MASTER_KEY",
    ]

    # Ordinary credentials: still a High injection finding, but not critical.
    DOES_NOT_ESCALATE = ["NPM_TOKEN", "SENTRY_DSN", "SLACK_WEBHOOK", "READ_ONLY_KEY"]

    def _ids_for(self, secret_name):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".github", "workflows", "w.yml"), _workflow_with_secret(secret_name))
            return [f.check_id for f in run_ci(root)]

    def test_high_privilege_names_escalate_to_critical(self):
        for name in self.ESCALATES:
            with self.subTest(secret=name):
                self.assertIn("ci.injection_with_high_privilege_secret_in_scope", self._ids_for(name))

    def test_ordinary_names_stay_high_not_critical(self):
        for name in self.DOES_NOT_ESCALATE:
            with self.subTest(secret=name):
                ids = self._ids_for(name)
                self.assertNotIn("ci.injection_with_high_privilege_secret_in_scope", ids)
                self.assertIn("ci.script_injection_in_run_block", ids)

    def test_dropped_literals_still_covered_by_shorter_fragments(self):
        """The two whole-name literals removed from the regex must stay
        covered, or this change would be a silent regression."""
        for name in ("SUPABASE_SERVICE_ROLE_KEY", "AWS_SECRET_ACCESS_KEY"):
            with self.subTest(secret=name):
                self.assertTrue(ci_checker.HIGH_PRIV_SECRET_NAME.search(name))


class TestDocsMatchTheCode(unittest.TestCase):
    """The list lives in three places on purpose (code, PLAYBOOK.md, and the
    skill) because two of them are prose an agent follows without running the
    code. That is exactly how it drifted before -- so assert they agree."""

    REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    TERMS = {"service_role", "admin", "root", "master", "write", "deploy", "aws_secret", "private_key"}

    def test_regex_contains_exactly_the_documented_terms(self):
        self.assertEqual(set(ci_checker.HIGH_PRIV_SECRET_NAME.pattern.split("(?i)(")[1].rstrip(")").split("|")), self.TERMS)

    def _assert_doc_lists_every_term(self, relpath):
        path = os.path.join(self.REPO_ROOT, relpath)
        if not os.path.isfile(path):
            self.skipTest(f"{relpath} not present")
        with open(path, encoding="utf-8") as fh:
            text = fh.read().lower()
        for term in sorted(self.TERMS):
            with self.subTest(doc=relpath, term=term):
                self.assertIn(term, text, f"{relpath} does not document '{term}'")

    def test_playbook_documents_every_term(self):
        self._assert_doc_lists_every_term("PLAYBOOK.md")

    def test_skill_documents_every_term(self):
        self._assert_doc_lists_every_term(os.path.join(".claude", "skills", "security-audit", "SKILL.md"))


if __name__ == "__main__":
    unittest.main()
