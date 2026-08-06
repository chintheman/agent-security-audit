"""Every test here mocks the LLM call -- never a real API request in CI,
per the plan's explicit requirement. The most important tests are the
redaction choke point (a secret-shaped string must never reach the
"outbound" call, even a mocked one) and the confidence-capping/source
tagging contract.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from asa import ai_assist, redact


def write(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


class TestProviderAndKey(unittest.TestCase):
    def test_missing_api_key_raises(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ai_assist.AIAssistError):
                ai_assist._provider_and_key()

    def test_defaults_to_anthropic(self):
        with mock.patch.dict(os.environ, {"ASA_LLM_API_KEY": "fake-key"}, clear=True):
            provider, key, model = ai_assist._provider_and_key()
            self.assertEqual(provider, "anthropic")
            self.assertEqual(key, "fake-key")

    def test_unknown_provider_raises(self):
        with mock.patch.dict(os.environ, {"ASA_LLM_API_KEY": "x", "ASA_LLM_PROVIDER": "not-a-real-provider"}, clear=True):
            with self.assertRaises(ai_assist.AIAssistError):
                ai_assist._provider_and_key()

    def test_model_override_respected(self):
        with mock.patch.dict(os.environ, {"ASA_LLM_API_KEY": "x", "ASA_LLM_MODEL": "custom-model"}, clear=True):
            _, _, model = ai_assist._provider_and_key()
            self.assertEqual(model, "custom-model")


class TestBuildPromptChokePoint(unittest.TestCase):
    def test_raises_on_credential_shaped_field(self):
        secret = "AIza" + "x" * 35
        with self.assertRaises(redact.SecretShapeDetected):
            ai_assist._build_prompt("field: {value}", value=secret)

    def test_clean_fields_pass_through(self):
        result = ai_assist._build_prompt("hello {name}", name="world")
        self.assertEqual(result, "hello world")

    def test_never_calls_llm_if_choke_point_trips(self):
        secret = "ghp_" + "a" * 36
        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            with self.assertRaises(redact.SecretShapeDetected):
                ai_assist._build_prompt("{value}", value=secret)
            mock_urlopen.assert_not_called()


class TestClassifyUnknownComponent(unittest.TestCase):
    def test_parses_valid_json_response(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "main.tf"), "resource \"aws_s3_bucket\" \"x\" {}\n")
            fake_response = json.dumps({"kind_guess": "terraform_config", "confidence": "high", "rationale": "has .tf-style resource blocks"})
            with mock.patch.dict(os.environ, {"ASA_LLM_API_KEY": "fake"}, clear=True), \
                 mock.patch("asa.ai_assist._call_llm", return_value=fake_response):
                result = ai_assist.classify_unknown_component(root, ["main.tf"])
            self.assertEqual(result["kind_guess"], "terraform_config")

    def test_confidence_capped_at_medium_even_if_model_claims_high(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "x.yaml"), "a: 1\n")
            fake_response = json.dumps({"kind_guess": "something", "confidence": "high", "rationale": "x"})
            with mock.patch.dict(os.environ, {"ASA_LLM_API_KEY": "fake"}, clear=True), \
                 mock.patch("asa.ai_assist._call_llm", return_value=fake_response):
                result = ai_assist.classify_unknown_component(root, ["x.yaml"])
            self.assertEqual(result["confidence"], "medium")

    def test_unparseable_response_degrades_gracefully(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "x.yaml"), "a: 1\n")
            with mock.patch.dict(os.environ, {"ASA_LLM_API_KEY": "fake"}, clear=True), \
                 mock.patch("asa.ai_assist._call_llm", return_value="not json at all, sorry"):
                result = ai_assist.classify_unknown_component(root, ["x.yaml"])
            self.assertEqual(result["kind_guess"], "unknown")
            self.assertEqual(result["confidence"], "low")

    def test_secret_in_sampled_file_content_is_masked_before_prompt(self):
        with tempfile.TemporaryDirectory() as root:
            secret = "AIza" + "z" * 35
            write(os.path.join(root, "config.yaml"), f"api_key: {secret}\n")
            captured = {}

            def fake_call_llm(prompt, **kwargs):
                captured["prompt"] = prompt
                return json.dumps({"kind_guess": "x", "confidence": "low", "rationale": "x"})

            with mock.patch.dict(os.environ, {"ASA_LLM_API_KEY": "fake"}, clear=True), \
                 mock.patch("asa.ai_assist._call_llm", side_effect=fake_call_llm):
                ai_assist.classify_unknown_component(root, ["config.yaml"])
            self.assertNotIn(secret, captured["prompt"])


class TestSuggestFix(unittest.TestCase):
    def test_returns_stripped_text(self):
        with mock.patch.dict(os.environ, {"ASA_LLM_API_KEY": "fake"}, clear=True), \
             mock.patch("asa.ai_assist._call_llm", return_value="  Do the thing.  \n"):
            result = ai_assist.suggest_fix({"category": "secrets", "check_id": "x.y", "title": "t", "file": "f", "variable_name": "V"})
        self.assertEqual(result, "Do the thing.")

    def test_stub_with_secret_shaped_title_raises(self):
        secret = "ghp_" + "b" * 36
        with mock.patch.dict(os.environ, {"ASA_LLM_API_KEY": "fake"}, clear=True):
            with self.assertRaises(redact.SecretShapeDetected):
                ai_assist.suggest_fix({"category": "secrets", "check_id": "x", "title": secret, "file": "f", "variable_name": "V"})


class TestFindUnrecognizedDirectories(unittest.TestCase):
    def test_finds_directory_with_unrecognized_config(self):
        from asa import manifest as manifest_mod
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "terraform", "main.tf"), "")
            write(os.path.join(root, "terraform", "variables.tf.json"), "{}")
            m = manifest_mod.build(root)
            candidates = ai_assist.find_unrecognized_directories(m, root)
            rels = [c["rel"] for c in candidates]
            self.assertIn("terraform", rels)

    def test_does_not_flag_already_recognized_directories(self):
        from asa import manifest as manifest_mod
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, "package.json"), "{}")
            m = manifest_mod.build(root)
            candidates = ai_assist.find_unrecognized_directories(m, root)
            rels = [c["rel"] for c in candidates]
            self.assertNotIn(".", rels)

    def test_capped_at_max_dirs(self):
        from asa import manifest as manifest_mod
        with tempfile.TemporaryDirectory() as root:
            for i in range(10):
                write(os.path.join(root, f"unknown{i}", "x.toml"), "")
            m = manifest_mod.build(root)
            candidates = ai_assist.find_unrecognized_directories(m, root, max_dirs=3)
            self.assertEqual(len(candidates), 3)


class TestLlmDispatch(unittest.TestCase):
    def test_anthropic_request_shape(self):
        fake_resp = mock.MagicMock()
        fake_resp.read.return_value = json.dumps({"content": [{"text": "hello"}]}).encode()
        fake_resp.__enter__.return_value = fake_resp
        with mock.patch.dict(os.environ, {"ASA_LLM_API_KEY": "fake", "ASA_LLM_PROVIDER": "anthropic"}, clear=True), \
             mock.patch("urllib.request.urlopen", return_value=fake_resp) as mock_open:
            result = ai_assist._call_llm("hi")
        self.assertEqual(result, "hello")
        req = mock_open.call_args[0][0]
        self.assertIn("anthropic.com", req.full_url)
        self.assertEqual(req.headers["X-api-key"], "fake")

    def test_openai_request_shape(self):
        fake_resp = mock.MagicMock()
        fake_resp.read.return_value = json.dumps({"choices": [{"message": {"content": "hello"}}]}).encode()
        fake_resp.__enter__.return_value = fake_resp
        with mock.patch.dict(os.environ, {"ASA_LLM_API_KEY": "fake", "ASA_LLM_PROVIDER": "openai"}, clear=True), \
             mock.patch("urllib.request.urlopen", return_value=fake_resp) as mock_open:
            result = ai_assist._call_llm("hi")
        self.assertEqual(result, "hello")
        req = mock_open.call_args[0][0]
        self.assertIn("openai.com", req.full_url)

    def test_malformed_response_raises_ai_assist_error(self):
        fake_resp = mock.MagicMock()
        fake_resp.read.return_value = json.dumps({"unexpected": "shape"}).encode()
        fake_resp.__enter__.return_value = fake_resp
        with mock.patch.dict(os.environ, {"ASA_LLM_API_KEY": "fake"}, clear=True), \
             mock.patch("urllib.request.urlopen", return_value=fake_resp):
            with self.assertRaises(ai_assist.AIAssistError):
                ai_assist._call_llm("hi")


if __name__ == "__main__":
    unittest.main()
