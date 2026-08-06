import inspect
import unittest

from asa import redact


class TestHash8(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(redact.hash8("hello"), redact.hash8("hello"))

    def test_different_values_differ(self):
        self.assertNotEqual(redact.hash8("hello"), redact.hash8("world"))

    def test_length_is_8(self):
        self.assertEqual(len(redact.hash8("anything")), 8)

    def test_empty_string_does_not_raise(self):
        # not used for masking (mask_literal short-circuits on empty), but
        # hash8 itself must not blow up on edge-case input
        self.assertEqual(len(redact.hash8("")), 8)


class TestMaskLiteralBoundaries(unittest.TestCase):
    """Exact-boundary cases -- this is where a masking bug hides."""

    def test_exact_4_char_value(self):
        secret = "aB3$"
        text = f"PASSWORD={secret}"
        masked = redact.mask_literal(text, secret)
        self.assertNotIn(secret, masked)
        self.assertIn("<redacted:len=4>", masked)

    def test_exact_8_char_value(self):
        secret = "aB3$xY9!"
        text = f"TOKEN={secret}"
        masked = redact.mask_literal(text, secret)
        self.assertNotIn(secret, masked)
        self.assertIn("<redacted:len=8>", masked)

    def test_value_with_regex_metacharacters(self):
        # a naive re.sub(value, placeholder, text) would either throw
        # (bad pattern) or silently fail to match -- mask_literal must use
        # plain str.replace, immune to this class of bug entirely.
        secret = "a.b*c$d^e(f)g[h]i"
        text = f"SECRET={secret} end"
        masked = redact.mask_literal(text, secret)
        self.assertNotIn(secret, masked)

    def test_value_with_backslashes(self):
        secret = r"pa\ss\word"
        text = f"PWD={secret}"
        masked = redact.mask_literal(text, secret)
        self.assertNotIn(secret, masked)

    def test_unicode_value(self):
        secret = "pässwörd-日本語-🔑"
        text = f"KEY={secret}"
        masked = redact.mask_literal(text, secret)
        self.assertNotIn(secret, masked)

    def test_empty_value_returns_text_unchanged(self):
        text = "KEY="
        self.assertEqual(redact.mask_literal(text, ""), text)

    def test_all_substrings_of_4_or_more_chars_gone(self):
        secret = "supersecretvalue12345"
        text = f"x = '{secret}'"
        masked = redact.mask_literal(text, secret)
        for i in range(len(secret) - 3):
            sub = secret[i : i + 4]
            self.assertNotIn(sub, masked, f"substring {sub!r} of the secret leaked into masked output")


class TestMaskWhitespaceVariants(unittest.TestCase):
    """Named regression test for the real incident: a `\\s`-based sed
    pattern silently failed to match on macOS's BSD sed, leaking a secret.
    redact.py's masking must not depend on any regex whitespace class or
    any external tool's regex dialect at all -- it uses str.replace for
    known values, which is dialect-independent by construction."""

    def test_mask_matches_on_non_gnu_whitespace_variants(self):
        variants = [
            "secretVal",
            "secret\tVal",
            "secret\n Val ue",
            "secret  Val ue",  # non-breaking space
        ]
        for secret in variants:
            with self.subTest(secret=repr(secret)):
                text = f"BEFORE {secret} AFTER"
                masked = redact.mask_literal(text, secret)
                self.assertNotIn(secret, masked)
                self.assertIn("BEFORE", masked)
                self.assertIn("AFTER", masked)

    def test_redact_module_never_shells_out(self):
        """Static guard: redact.py must not import subprocess/os.system or
        invoke sed/grep as an external process for masking. Checks actual
        code constructs, not prose -- the module's own docstring discusses
        the BSD-sed incident by name, which a naive substring check on the
        whole source would false-positive on."""
        src = inspect.getsource(redact)
        # strip the module docstring (the first triple-quoted block) before
        # scanning, so documentation mentioning "sed"/"grep" by name in
        # prose doesn't trip this check -- only real code matters here.
        code_only = src.split('"""', 2)[-1] if src.count('"""') >= 2 else src
        for forbidden in (
            "import subprocess",
            "os.system(",
            "os.popen(",
            "subprocess.run(",
            "subprocess.call(",
            "subprocess.Popen(",
            "subprocess.check_",
        ):
            self.assertNotIn(forbidden, code_only, f"redact.py must not shell out via {forbidden!r}")


class TestCredentialShapeDetection(unittest.TestCase):
    def test_detects_known_shapes(self):
        samples = {
            "github_pat_classic": "ghp_" + "a" * 36,
            "google_api_key": "AIza" + "b" * 35,
            "anthropic_api_key": "sk-ant-" + "c" * 25,
        }
        for name, value in samples.items():
            with self.subTest(name=name):
                hits = redact.find_credential_shapes(f"KEY={value}")
                self.assertTrue(any(h[0] == name for h in hits), f"expected {name} to be detected in {value!r}")

    def test_ordinary_text_has_no_hits(self):
        hits = redact.find_credential_shapes("the quick brown fox jumps over the lazy dog")
        self.assertEqual(hits, [])

    def test_mask_credential_shapes_removes_value(self):
        value = "ghp_" + "a" * 36
        text = f"export GITHUB_TOKEN={value}"
        masked = redact.mask_credential_shapes(text)
        self.assertNotIn(value, masked)
        self.assertIn("<redacted:", masked)

    def test_filesystem_paths_are_not_flagged_as_generic_secrets(self):
        """Regression test: the generic_high_entropy_hex_or_b64 pattern
        used to include "/" in its character class, so it matched straight
        through entire paths (e.g. a macOS tempdir like
        /var/folders/bn/k3vy847j0msf95q2sf4n3c980000gn/T/tmpXXXXXXXX) as
        one long "high-entropy" run. Caught by ai_assist.py's tests
        refusing to send a path as a prompt field."""
        paths = [
            "/var/folders/bn/k3vy847j0msf95q2sf4n3c980000gn/T/tmprojr8n4h",
            "/Users/someone/projects/my-project-name/node_modules/some-package/index.js",
            "/home/user/.hermes/profiles/health-wellness/cron/morning_journal.py",
        ]
        for path in paths:
            with self.subTest(path=path):
                hits = redact.find_credential_shapes(path)
                self.assertEqual(hits, [], f"path {path!r} was incorrectly flagged as credential-shaped: {hits}")


class TestAssertNoSecretShape(unittest.TestCase):
    def test_raises_on_credential_shaped_text(self):
        value = "AIza" + "x" * 35
        with self.assertRaises(redact.SecretShapeDetected):
            redact.assert_no_secret_shape(f"here is a key: {value}")

    def test_does_not_raise_on_clean_text(self):
        redact.assert_no_secret_shape("this text has no secrets in it at all")


class TestMakeSnippet(unittest.TestCase):
    def test_masks_known_value(self):
        secret = "hunter2verysecret"
        line = f'password: "{secret}"'
        snippet = redact.make_snippet(line, known_value=secret)
        self.assertNotIn(secret, snippet)

    def test_masks_unrelated_credential_shape_on_same_line(self):
        known = "somevalue"
        other = "ghp_" + "z" * 36
        line = f"PASSWORD={known}  # also see GITHUB_TOKEN={other}"
        snippet = redact.make_snippet(line, known_value=known)
        self.assertNotIn(known, snippet)
        self.assertNotIn(other, snippet)

    def test_truncates_long_lines(self):
        line = "x" * 500
        snippet = redact.make_snippet(line, max_len=50)
        self.assertLessEqual(len(snippet), 51)  # 50 chars + ellipsis


class TestEvidenceDict(unittest.TestCase):
    def test_never_includes_raw_value(self):
        secret = "topsecretvalue123"
        ev = redact.evidence_dict(
            value=secret,
            file="config.yaml",
            line=5,
            variable_name="API_KEY",
            raw_line=f"API_KEY={secret}",
        )
        blob = repr(ev)
        self.assertNotIn(secret, blob)
        self.assertEqual(ev["value_length"], len(secret))
        self.assertEqual(ev["value_hash8"], redact.hash8(secret))
        self.assertEqual(ev["variable_name"], "API_KEY")


if __name__ == "__main__":
    unittest.main()
