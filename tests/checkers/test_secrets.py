import os
import re
import subprocess
import tempfile
import unittest

from asa import manifest as manifest_mod
from asa.checkers import secrets as secrets_checker


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def run_secrets(root, context=None):
    m = manifest_mod.build(root)
    return secrets_checker.run(m, root, context)


class TestHardcodedValueInsteadOfEnvRef(unittest.TestCase):
    def test_flags_literal_credential_value(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: hunter2isnotarealpasswordbutlooksok\n")
            findings = run_secrets(root)
            ids = [f.check_id for f in findings]
            self.assertIn("secrets.hardcoded_value_instead_of_env_ref", ids)

    def test_does_not_flag_env_var_reference(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "PASSWORD: ${DB_PASSWORD}\n")
            findings = run_secrets(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("secrets.hardcoded_value_instead_of_env_ref", ids)

    def test_does_not_flag_placeholder_values(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "API_KEY: changeme\n")
            findings = run_secrets(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("secrets.hardcoded_value_instead_of_env_ref", ids)

    def test_does_not_flag_non_credential_keys(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "config.yaml"), "replicas: 3\ndebug: true\n")
            findings = run_secrets(root)
            self.assertEqual(findings, [])

    def test_skips_dotenv_files(self):
        # .env files ARE the literal-value store by design -- not a finding
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".env"), "PASSWORD=hunter2isnotarealpasswordbutlooksok\n")
            findings = run_secrets(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("secrets.hardcoded_value_instead_of_env_ref", ids)

    def test_evidence_never_contains_raw_value(self):
        with tempfile.TemporaryDirectory() as root:
            secret = "hunter2isnotarealpasswordbutlooksok"
            write(os.path.join(root, "config.yaml"), f"PASSWORD: {secret}\n")
            findings = run_secrets(root)
            for f in findings:
                self.assertNotIn(secret, repr(f.to_dict()))


class TestCredentialShapedStringAnywhere(unittest.TestCase):
    def test_flags_known_shape_in_source_code(self):
        with tempfile.TemporaryDirectory() as root:
            key = "AIza" + "q" * 35
            write(os.path.join(root, "app.py"), f'GOOGLE_KEY = "{key}"\n')
            findings = run_secrets(root)
            ids = [f.check_id for f in findings]
            self.assertIn("secrets.credential_shaped_string_anywhere", ids)

    def test_ordinary_code_has_no_hits(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "app.py"), "def add(a, b):\n    return a + b\n")
            findings = run_secrets(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("secrets.credential_shaped_string_anywhere", ids)

    def test_skips_dotenv_files(self):
        with tempfile.TemporaryDirectory() as root:
            key = "AIza" + "q" * 35
            write(os.path.join(root, ".env"), f"GOOGLE_KEY={key}\n")
            findings = run_secrets(root)
            ids = [f.check_id for f in findings]
            self.assertNotIn("secrets.credential_shaped_string_anywhere", ids)

    def test_evidence_never_contains_raw_value(self):
        with tempfile.TemporaryDirectory() as root:
            key = "AIza" + "q" * 35
            write(os.path.join(root, "app.py"), f'GOOGLE_KEY = "{key}"\n')
            findings = run_secrets(root)
            for f in findings:
                self.assertNotIn(key, repr(f.to_dict()))


class TestDotenvWorldReadable(unittest.TestCase):
    def test_flags_world_readable_env_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o644)
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.dotenv_world_readable"]
            self.assertEqual(len(hits), 1)
            self.assertTrue(hits[0].auto_fixable)

    def test_does_not_flag_owner_only_env_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o600)
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.dotenv_world_readable"]
            self.assertEqual(hits, [])


class TestDotenvPermissionDrift(unittest.TestCase):
    def test_no_baseline_means_no_findings(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o644)
            findings = run_secrets(root, context=None)
            hits = [f for f in findings if f.check_id == "secrets.dotenv_permission_drift"]
            self.assertEqual(hits, [])

    def test_flags_loosened_permissions_vs_baseline(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o644)
            baseline = {"baseline_modes": {path: 0o600}}
            findings = run_secrets(root, context=baseline)
            hits = [f for f in findings if f.check_id == "secrets.dotenv_permission_drift"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].severity.value, "critical")

    def test_no_drift_when_baseline_matches_current(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".env")
            write(path, "KEY=value\n")
            os.chmod(path, 0o600)
            baseline = {"baseline_modes": {path: 0o600}}
            findings = run_secrets(root, context=baseline)
            hits = [f for f in findings if f.check_id == "secrets.dotenv_permission_drift"]
            self.assertEqual(hits, [])


class TestGenericEnvVarNameCollision(unittest.TestCase):
    def test_flags_password_reused_across_files(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "toolA", ".env"), "PASSWORD=someactualvalue123\n")
            write(os.path.join(root, "toolB", ".env"), "PASSWORD=someactualvalue123\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.generic_env_var_name_collision"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].evidence.variable_name, "PASSWORD")

    def test_specific_name_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "toolA", ".env"), "STRIPE_SECRET_KEY=someactualvalue123\n")
            write(os.path.join(root, "toolB", ".env"), "STRIPE_SECRET_KEY=someactualvalue123\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.generic_env_var_name_collision"]
            self.assertEqual(hits, [])

    def test_single_occurrence_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, ".env"), "PASSWORD=someactualvalue123\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.generic_env_var_name_collision"]
            self.assertEqual(hits, [])


class TestDuplicateSecretValueDifferentNames(unittest.TestCase):
    def test_flags_same_value_different_names(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "toolA", ".env"), "SUBSTACK_PASSWORD=sharedvalue123456\n")
            write(os.path.join(root, "toolB", ".env"), "GARMIN_PASSWORD=sharedvalue123456\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.duplicate_secret_value_different_names"]
            self.assertEqual(len(hits), 1)

    def test_same_name_same_value_not_flagged_as_duplicate(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "toolA", ".env"), "SHARED_KEY=sharedvalue123456\n")
            write(os.path.join(root, "toolB", ".env"), "SHARED_KEY=sharedvalue123456\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.duplicate_secret_value_different_names"]
            self.assertEqual(hits, [])

    def test_different_values_not_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "toolA", ".env"), "KEY_A=valueoneabcdef\n")
            write(os.path.join(root, "toolB", ".env"), "KEY_B=valuetwoabcdef\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.duplicate_secret_value_different_names"]
            self.assertEqual(hits, [])

    def test_evidence_never_contains_raw_value(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "toolA", ".env"), "SUBSTACK_PASSWORD=sharedvalue123456\n")
            write(os.path.join(root, "toolB", ".env"), "GARMIN_PASSWORD=sharedvalue123456\n")
            findings = run_secrets(root)
            for f in findings:
                self.assertNotIn("sharedvalue123456", repr(f.to_dict()))


@unittest.skipIf(subprocess.run(["which", "git"], capture_output=True).returncode != 0, "git not installed")
class TestSecretInGitHistory(unittest.TestCase):
    def _git(self, root, *args):
        subprocess.run(["git", *args], cwd=root, capture_output=True, text=True,
                        env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.com",
                             "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.com"})

    def test_flags_secret_committed_then_deleted(self):
        with tempfile.TemporaryDirectory() as root:
            self._git(root, "init", "-q")
            secret_path = os.path.join(root, "creds.pem")
            key = "AIza" + "w" * 35
            write(secret_path, f"GOOGLE_KEY={key}\n")
            self._git(root, "add", "creds.pem")
            self._git(root, "commit", "-q", "-m", "add creds by mistake")
            os.remove(secret_path)
            self._git(root, "add", "-A")
            self._git(root, "commit", "-q", "-m", "remove creds")

            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.secret_in_git_history"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].severity.value, "critical")
            # never leak the actual key even though it's deep in git history output
            for f in findings:
                self.assertNotIn(key, repr(f.to_dict()))

    def test_no_git_dir_no_findings(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "app.py"), "print('hi')\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.secret_in_git_history"]
            self.assertEqual(hits, [])


class TestCleanProjectNoFalsePositives(unittest.TestCase):
    def test_clean_project_yields_zero_findings(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), '{"name": "clean", "version": "1.0.0"}\n')
            write(os.path.join(root, "src", "index.js"), "console.log('hello world');\n")
            write(os.path.join(root, "README.md"), "# Clean project\n\nNothing to see here.\n")
            write(os.path.join(root, "config.yaml"), "replicas: 3\ndebug: false\ntimeout_seconds: 30\n")
            write(os.path.join(root, ".env"), "PASSWORD=changeme\n")  # placeholder, correctly-permissioned below
            os.chmod(os.path.join(root, ".env"), 0o600)
            findings = run_secrets(root)
            self.assertEqual(findings, [], f"expected zero findings on a clean project, got: {[f.check_id for f in findings]}")


FIRST_12_WORDS = "abandon ability able about above absent absorb abstract absurd abuse access accident"
FIRST_15_WORDS = FIRST_12_WORDS + " account accuse achieve"
FIRST_24_WORDS = FIRST_15_WORDS + " acid acoustic acquire across act action actor actress actual"
FIRST_11_WORDS = "abandon ability able about above absent absorb abstract absurd abuse access"
# 13 consecutive real wordlist words -- deliberately NOT a valid seed-phrase
# length (12/15/18/21/24), so this must never trigger a finding.
THIRTEEN_WORD_RUN = "arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma"


class TestSeedPhraseDetected(unittest.TestCase):
    def test_flags_12_consecutive_wordlist_words(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "notes.txt"), FIRST_12_WORDS + "\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.seed_phrase_detected"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].severity.value, "critical")
            self.assertEqual(hits[0].evidence.detail["word_count"], 12)
            self.assertEqual(hits[0].evidence.line, 1)

    def test_flags_24_word_run(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "notes.txt"), FIRST_24_WORDS + "\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.seed_phrase_detected"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].evidence.detail["word_count"], 24)

    def test_does_not_flag_11_words(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "notes.txt"), FIRST_11_WORDS + "\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.seed_phrase_detected"]
            self.assertEqual(hits, [])

    def test_does_not_flag_run_of_invalid_length(self):
        # 13 consecutive real wordlist words -- not one of 12/15/18/21/24
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "notes.txt"), THIRTEEN_WORD_RUN + "\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.seed_phrase_detected"]
            self.assertEqual(hits, [])

    def test_mixed_case_breaks_the_run(self):
        with tempfile.TemporaryDirectory() as root:
            capitalized = "Abandon " + " ".join(FIRST_12_WORDS.split()[1:])
            write(os.path.join(root, "notes.txt"), capitalized + "\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.seed_phrase_detected"]
            self.assertEqual(hits, [])  # only 11 lowercase wordlist words left in a row

    def test_punctuation_breaks_the_run(self):
        with tempfile.TemporaryDirectory() as root:
            words = FIRST_12_WORDS.split()
            words[0] = words[0] + ","  # "abandon," no longer an exact wordlist token
            write(os.path.join(root, "notes.txt"), " ".join(words) + "\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.seed_phrase_detected"]
            self.assertEqual(hits, [])  # remaining run is 11 words, not a valid length

    def test_run_split_one_word_per_line_still_flagged(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "notes.txt"), "\n".join(FIRST_12_WORDS.split()) + "\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.seed_phrase_detected"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].evidence.detail["word_count"], 12)
            self.assertEqual(hits[0].evidence.line, 1)  # run starts on line 1

    def test_skips_the_wordlist_file_itself(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "bip39_wordlist.py"), FIRST_12_WORDS + "\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.seed_phrase_detected"]
            self.assertEqual(hits, [])

    def test_evidence_never_contains_the_phrase(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "notes.txt"), FIRST_12_WORDS + "\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.seed_phrase_detected"]
            self.assertEqual(len(hits), 1)
            dumped = repr(hits[0].to_dict())
            # word-boundary match -- a plain substring check would false-positive
            # on "able" inside the schema's own "auto_fixable" field name
            for word in FIRST_12_WORDS.split():
                self.assertIsNone(re.search(rf"\b{re.escape(word)}\b", dumped), f"{word!r} leaked into finding output")

    def test_fixture_project_on_disk(self):
        # Edge case using a real fixture directory (not a tempfile) --
        # tests/fixtures/seed_phrase_project/wallet-notes.txt carries a
        # 12-word run, config.yaml and README.md are clean and must stay
        # silent.
        fixture_root = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "fixtures", "seed_phrase_project"
        )
        findings = run_secrets(fixture_root)
        hits = [f for f in findings if f.check_id == "secrets.seed_phrase_detected"]
        self.assertEqual(len(hits), 1, f"expected exactly one seed-phrase finding, got: {[(f.location) for f in hits]}")
        self.assertEqual(hits[0].evidence.file, "wallet-notes.txt")
        self.assertEqual(hits[0].evidence.detail["word_count"], 12)


@unittest.skipIf(subprocess.run(["which", "git"], capture_output=True).returncode != 0, "git not installed")
class TestSeedPhraseInGitHistory(unittest.TestCase):
    def _git(self, root, *args):
        subprocess.run(["git", *args], cwd=root, capture_output=True, text=True,
                        env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.com",
                             "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.com"})

    def test_flags_phrase_committed_then_deleted(self):
        with tempfile.TemporaryDirectory() as root:
            self._git(root, "init", "-q")
            secret_path = os.path.join(root, "wallet-backup.txt")
            write(secret_path, FIRST_12_WORDS + "\n")
            self._git(root, "add", "wallet-backup.txt")
            self._git(root, "commit", "-q", "-m", "backup wallet by mistake")
            os.remove(secret_path)
            self._git(root, "add", "-A")
            self._git(root, "commit", "-q", "-m", "remove backup")

            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.seed_phrase_detected"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].severity.value, "critical")
            dumped = repr([f.to_dict() for f in findings])
            for word in FIRST_12_WORDS.split():
                self.assertIsNone(re.search(rf"\b{re.escape(word)}\b", dumped), f"{word!r} leaked into finding output")

    def test_no_git_dir_no_findings(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "app.py"), "print('hi')\n")
            findings = run_secrets(root)
            hits = [f for f in findings if f.check_id == "secrets.seed_phrase_detected"]
            self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
