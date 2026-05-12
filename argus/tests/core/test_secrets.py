"""Unit tests for argus.core.secrets — credential resolution from config.

The contract under test: a scanner asks for a credential field by name,
the resolver picks up either ``<field>_env`` (an env-var name reference)
or ``<field>`` (a literal, back-compat path) and returns the plaintext
value — or ``None`` if the credential is not configured.

These tests guard the precedence rules, the warning behavior, and the
``stdin_override`` escape hatch the CLI will eventually use.
"""

from __future__ import annotations

import logging

import pytest

from argus.core.secrets import (
    looks_like_literal_secret,
    resolve_secret,
    validate_env_var_name,
)


class TestResolveSecret:
    def test_env_var_name_reference_reads_named_env_var(self):
        config = {"registry_password_env": "REGISTRY_TOKEN"}
        env = {"REGISTRY_TOKEN": "secret-from-env"}

        result = resolve_secret(config, "registry_password", env=env)

        assert result == "secret-from-env"

    def test_literal_value_returned_directly(self):
        config = {"registry_password": "literal-pass"}

        result = resolve_secret(config, "registry_password", env={})

        assert result == "literal-pass"

    def test_returns_none_when_neither_form_configured(self):
        result = resolve_secret({}, "registry_password", env={})

        assert result is None

    def test_stdin_override_wins_over_env_ref(self):
        config = {"registry_password_env": "REGISTRY_TOKEN"}
        env = {"REGISTRY_TOKEN": "from-env"}

        result = resolve_secret(
            config, "registry_password", env=env, stdin_override="from-stdin",
        )

        assert result == "from-stdin"

    def test_stdin_override_wins_over_literal(self):
        config = {"registry_password": "literal-pass"}

        result = resolve_secret(
            config, "registry_password", env={}, stdin_override="from-stdin",
        )

        assert result == "from-stdin"

    def test_stdin_override_resolves_even_when_nothing_else_configured(self):
        result = resolve_secret(
            {}, "registry_password", env={}, stdin_override="from-stdin",
        )

        assert result == "from-stdin"

    def test_env_ref_wins_over_literal_when_both_set(self, caplog):
        config = {
            "registry_password": "literal-pass",
            "registry_password_env": "REGISTRY_TOKEN",
        }
        env = {"REGISTRY_TOKEN": "env-pass"}

        with caplog.at_level(logging.WARNING, logger="argus"):
            result = resolve_secret(config, "registry_password", env=env)

        assert result == "env-pass"
        # User gets a clear warning that the literal is shadowed
        assert any(
            "registry_password" in r.message and "registry_password_env" in r.message
            for r in caplog.records
        )

    def test_unset_env_var_returns_none_with_warning(self, caplog):
        config = {"registry_password_env": "MISSING_VAR"}

        with caplog.at_level(logging.WARNING, logger="argus"):
            result = resolve_secret(config, "registry_password", env={})

        assert result is None
        assert any("MISSING_VAR" in r.message for r in caplog.records)

    def test_env_ref_with_non_string_value_returns_none_with_warning(self, caplog):
        # YAML accidentally typed as a list — most likely user mistake
        config = {"registry_password_env": ["REGISTRY_TOKEN"]}

        with caplog.at_level(logging.WARNING, logger="argus"):
            result = resolve_secret(config, "registry_password", env={})

        assert result is None
        assert any("must be a string" in r.message for r in caplog.records)

    def test_literal_non_string_returns_none(self):
        # YAML accidentally typed as an int
        config = {"registry_password": 12345}

        result = resolve_secret(config, "registry_password", env={})

        assert result is None

    def test_literal_looking_like_vendor_secret_warns(self, caplog):
        # ghp_ prefix is a GitHub PAT — should never be a literal
        config = {"registry_password": "ghp_" + "x" * 36}

        with caplog.at_level(logging.WARNING, logger="argus"):
            result = resolve_secret(config, "registry_password", env={})

        assert result == "ghp_" + "x" * 36
        assert any("looks like a literal" in r.message for r in caplog.records)

    def test_literal_basic_auth_password_does_not_warn(self, caplog):
        # No vendor prefix — we can't reliably detect this, so we
        # don't try. gitleaks covers that detection space.
        config = {"registry_password": "hunter2"}

        with caplog.at_level(logging.WARNING, logger="argus"):
            result = resolve_secret(config, "registry_password", env={})

        assert result == "hunter2"
        assert not any("looks like a literal" in r.message for r in caplog.records)

    def test_uses_os_environ_when_env_arg_omitted(self, monkeypatch):
        monkeypatch.setenv("ARGUS_TEST_TOKEN", "from-os-environ")
        config = {"registry_password_env": "ARGUS_TEST_TOKEN"}

        result = resolve_secret(config, "registry_password")

        assert result == "from-os-environ"

    def test_field_without_env_suffix_distinct(self):
        # 'registry_password_env_xyz' is NOT confused with the env-ref shape
        config = {"registry_password_env_xyz": "REGISTRY_TOKEN"}

        result = resolve_secret(config, "registry_password", env={})

        # Neither <field> nor <field>_env is present → None
        assert result is None


class TestValidateEnvVarName:
    @pytest.mark.parametrize("name", [
        "REGISTRY_TOKEN",       # canonical uppercase
        "registry_token",       # lowercase accepted
        "_PRIVATE",             # leading underscore
        "X",                    # single char
        "Mixed_Case_99",        # mixed case + digits
    ])
    def test_valid_names(self, name):
        assert validate_env_var_name(name) is True

    @pytest.mark.parametrize("name", [
        "1STARTS_WITH_DIGIT",   # digits-first rejected
        "HAS SPACES",            # whitespace rejected
        "HAS-DASH",              # dash rejected
        "HAS.DOT",               # dot rejected
        "",                      # empty rejected
        "$VAR",                  # punctuation rejected
    ])
    def test_invalid_names(self, name):
        assert validate_env_var_name(name) is False

    def test_non_string_rejected(self):
        assert validate_env_var_name(None) is False
        assert validate_env_var_name(123) is False
        assert validate_env_var_name(["FOO"]) is False


class TestLooksLikeLiteralSecret:
    @pytest.mark.parametrize("value", [
        "ghp_" + "a" * 36,                # GitHub PAT
        "gho_" + "a" * 36,                # GitHub OAuth
        "AKIAIOSFODNN7EXAMPLE",           # AWS access key
        "ASIA" + "X" * 16,                # AWS STS key
        "xoxb-1234567890-1234-abc",       # Slack bot token
        "glpat-aaaaaaaaaaaaaaaaaaa",      # GitLab PAT
        "sk_live_" + "a" * 24,            # Stripe live secret
        "AIzaSyD" + "x" * 32,             # Google API key
        "npm_" + "a" * 36,                # npm publish token
    ])
    def test_matches_known_vendor_prefixes(self, value):
        assert looks_like_literal_secret(value) is True

    @pytest.mark.parametrize("value", [
        "hunter2",                        # basic password
        "registry.internal.corp",         # registry hostname
        "myorg/myimage:1.2.3",            # image ref
        "sk_test_" + "a" * 24,            # Stripe TEST key — deliberately not matched
        "",                               # empty
        "${REGISTRY_TOKEN}",              # shell-template placeholder
    ])
    def test_does_not_match_non_secret_strings(self, value):
        assert looks_like_literal_secret(value) is False

    def test_non_string_returns_false(self):
        assert looks_like_literal_secret(None) is False
        assert looks_like_literal_secret(12345) is False
