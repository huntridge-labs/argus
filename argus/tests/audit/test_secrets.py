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


class TestMaskSecretsInObj:
    """Recursive walker — defense-in-depth for audit-trail writes."""

    def test_masks_string_at_root(self):
        from argus.audit.secrets import mask_secrets_in_obj
        result = mask_secrets_in_obj("token=ghp_supersecret123456789")
        assert REDACTED in result
        assert "ghp_supersecret" not in result

    def test_masks_string_in_dict_value(self):
        from argus.audit.secrets import mask_secrets_in_obj
        result = mask_secrets_in_obj({
            "config_path": "argus.yml",
            "auth_header": "Bearer eyJhbGc.signature",
        })
        assert result["config_path"] == "argus.yml"
        assert REDACTED in result["auth_header"]
        assert "eyJhbGc" not in result["auth_header"]

    def test_masks_nested_dict(self):
        from argus.audit.secrets import mask_secrets_in_obj
        result = mask_secrets_in_obj({
            "phase": "scan",
            "env": {
                "REGISTRY_TOKEN": "AKIA1234567890ABCDEF",
                "PATH": "/usr/bin",
            },
        })
        assert REDACTED in result["env"]["REGISTRY_TOKEN"]
        assert result["env"]["PATH"] == "/usr/bin"
        assert result["phase"] == "scan"

    def test_masks_list_of_strings(self):
        from argus.audit.secrets import mask_secrets_in_obj
        result = mask_secrets_in_obj([
            "docker run",
            "password=hunter2",
            "myapp:latest",
        ])
        assert result[0] == "docker run"
        assert REDACTED in result[1]
        assert "hunter2" not in result[1]
        assert result[2] == "myapp:latest"

    def test_masks_through_tuple(self):
        from argus.audit.secrets import mask_secrets_in_obj
        result = mask_secrets_in_obj(("normal", "token=sk-abc123def456ghi789"))
        assert isinstance(result, tuple)
        assert result[0] == "normal"
        assert REDACTED in result[1]

    def test_scalars_pass_through(self):
        from argus.audit.secrets import mask_secrets_in_obj
        assert mask_secrets_in_obj(42) == 42
        assert mask_secrets_in_obj(3.14) == 3.14
        assert mask_secrets_in_obj(True) is True
        assert mask_secrets_in_obj(None) is None

    def test_does_not_mutate_input(self):
        from argus.audit.secrets import mask_secrets_in_obj
        original = {"creds": {"token": "ghp_supersecret123456"}}
        result = mask_secrets_in_obj(original)
        # Caller's original is untouched
        assert original["creds"]["token"] == "ghp_supersecret123456"
        # Returned copy is masked
        assert "ghp_supersecret" not in result["creds"]["token"]

    def test_deeply_nested_mix(self):
        """Realistic shape: dict of lists of dicts of strings."""
        from argus.audit.secrets import mask_secrets_in_obj
        result = mask_secrets_in_obj({
            "phases": [
                {"name": "init", "command": ["argus", "scan"]},
                {"name": "auth", "command": ["docker", "login", "-p",
                                              "ghp_secret_1234567890abcdef"]},
            ],
        })
        # Non-secret strings preserved
        assert result["phases"][0]["command"] == ["argus", "scan"]
        # Secret-shaped string masked even at depth 4
        assert "ghp_secret" not in result["phases"][1]["command"][3]
        assert REDACTED in result["phases"][1]["command"][3]

    def test_dict_keys_not_masked(self):
        """Keys pass through unchanged — masking them would break consumers."""
        from argus.audit.secrets import mask_secrets_in_obj
        result = mask_secrets_in_obj({"ghp_keyname": "regular value"})
        assert "ghp_keyname" in result  # key intact
        assert result["ghp_keyname"] == "regular value"

    def test_unknown_object_passes_through(self):
        """Custom types we don't recognize pass through unchanged."""
        from argus.audit.secrets import mask_secrets_in_obj

        class Custom:
            pass

        obj = Custom()
        assert mask_secrets_in_obj(obj) is obj
