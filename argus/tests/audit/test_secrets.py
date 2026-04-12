"""Tests for argus.audit.secrets -- secret masking."""

import pytest

from argus.audit.secrets import mask_secrets


REDACTED = "<REDACTED>"


class TestMaskSecrets:
    """Verify that sensitive patterns are redacted."""

    def test_url_with_embedded_token(self):
        msg = "cloning https://user:ghp_abc123def@github.com/repo"
        result = mask_secrets(msg)
        assert "ghp_abc123def" not in result
        assert REDACTED in result

    def test_token_equals(self):
        result = mask_secrets("token=supersecret123")
        assert "supersecret123" not in result
        assert "token=" in result

    def test_token_colon_space(self):
        result = mask_secrets("Token: my-secret-value")
        assert "my-secret-value" not in result
        assert "Token: " in result

    def test_password_equals(self):
        result = mask_secrets("password=hunter2")
        assert "hunter2" not in result
        assert "password=" in result

    def test_password_colon(self):
        result = mask_secrets("Password: mypass123")
        assert "mypass123" not in result

    def test_bearer_token(self):
        result = mask_secrets("Authorization: Bearer eyJhbGciOiJ...")
        assert "eyJhbGciOiJ" not in result
        assert "Bearer " in result

    def test_github_pat(self):
        result = mask_secrets("using github_pat_abcdef1234567890")
        assert "github_pat_abcdef1234567890" not in result
        assert REDACTED in result

    def test_github_ghp_token(self):
        result = mask_secrets("GITHUB_TOKEN=ghp_1234567890abcdef")
        assert "ghp_1234567890abcdef" not in result

    def test_github_gho_token(self):
        result = mask_secrets("oauth gho_abcdef1234567890xyz")
        assert "gho_abcdef1234567890xyz" not in result

    def test_aws_access_key(self):
        result = mask_secrets("aws_key=AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert REDACTED in result

    def test_openai_api_key(self):
        result = mask_secrets("key=sk-abcdefghij1234567890abcdefghij")
        assert "sk-abcdefghij1234567890abcdefghij" not in result

    def test_no_false_positives_on_plain_text(self):
        msg = "scanning /workspace/src for vulnerabilities"
        assert mask_secrets(msg) == msg

    def test_empty_string(self):
        assert mask_secrets("") == ""

    def test_multiple_secrets_in_one_message(self):
        msg = "token=abc123 password=hunter2"
        result = mask_secrets(msg)
        assert "abc123" not in result
        assert "hunter2" not in result

    def test_case_insensitive_token(self):
        result = mask_secrets("TOKEN=mysecret")
        assert "mysecret" not in result

    def test_case_insensitive_bearer(self):
        result = mask_secrets("bearer abc123def456ghi789jkl")
        assert "abc123def456ghi789jkl" not in result
