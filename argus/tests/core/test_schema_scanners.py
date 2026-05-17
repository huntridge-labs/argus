"""Tests for validate_config's per-scanner block validation.

Locks in the contract: credential fields accept either ``<field>``
(literal, warned for vendor-shaped values) or ``<field>_env`` (env-var
name reference, required to be a valid POSIX identifier). ZAP's nested
``auth`` sub-block, ``cmd_options`` list, and ``max_duration_minutes``
integer are validated at the same layer so authoring mistakes surface
during ``argus validate`` instead of failing silently at scan time.
"""

from __future__ import annotations

from argus.core.schema import validate_config


def _errors(data: dict) -> list:
    return [e for e in validate_config(data) if e.level == "error"]


def _warnings(data: dict) -> list:
    return [e for e in validate_config(data) if e.level == "warning"]


def _has_at(items, path_substr: str, msg_substr: str = "") -> bool:
    return any(path_substr in i.path and msg_substr in i.message for i in items)


# --------------------------------------------------------------------- #
# Credential field validation — registry_username / registry_password   #
# --------------------------------------------------------------------- #


class TestCredentialFields:
    def test_env_ref_with_valid_identifier_accepted(self):
        cfg = {"scanners": {"zap": {
            "registry_username_env": "REGISTRY_USER",
            "registry_password_env": "REGISTRY_TOKEN",
        }}}
        assert _errors(cfg) == []

    def test_env_ref_with_invalid_identifier_errors(self):
        cfg = {"scanners": {"zap": {
            "registry_password_env": "1STARTS_WITH_DIGIT",
        }}}
        errs = _errors(cfg)
        assert _has_at(errs, "scanners.zap.registry_password_env", "not a valid")

    def test_env_ref_with_non_string_errors(self):
        cfg = {"scanners": {"zap": {
            "registry_password_env": ["REGISTRY_TOKEN"],
        }}}
        errs = _errors(cfg)
        assert _has_at(errs, "scanners.zap.registry_password_env", "string")

    def test_literal_basic_password_accepted_no_warning(self):
        # Non-vendor-shaped literal: works for back-compat, no warning.
        cfg = {"scanners": {"container": {"registry_password": "hunter2"}}}
        assert _errors(cfg) == []
        warns = _warnings(cfg)
        assert not _has_at(warns, "scanners.container.registry_password", "Looks like")

    def test_literal_vendor_shaped_warns(self):
        # ghp_ prefix is a GitHub PAT — should never be a literal.
        cfg = {"scanners": {"container": {
            "registry_password": "ghp_" + "a" * 36,
        }}}
        warns = _warnings(cfg)
        assert _has_at(warns, "scanners.container.registry_password", "Looks like")

    def test_both_literal_and_env_ref_warns(self):
        cfg = {"scanners": {"container": {
            "registry_password": "literal",
            "registry_password_env": "REGISTRY_TOKEN",
        }}}
        warns = _warnings(cfg)
        assert _has_at(
            warns, "scanners.container.registry_password",
            "Both 'registry_password' and 'registry_password_env'",
        )


# --------------------------------------------------------------------- #
# ZAP auth sub-block                                                    #
# --------------------------------------------------------------------- #


class TestZapAuthBlock:
    def test_valid_context_file_with_env_refs(self):
        cfg = {"scanners": {"zap": {"auth": {
            "context_file": ".zap/context.xml",
            "username_env": "ZAP_APP_USER",
            "password_env": "ZAP_APP_PASSWORD",
        }}}}
        assert _errors(cfg) == []

    def test_unknown_auth_key_warns(self):
        cfg = {"scanners": {"zap": {"auth": {
            "context_file": ".zap/context.xml",
            "typoed_key": "x",
        }}}}
        warns = _warnings(cfg)
        assert _has_at(warns, "scanners.zap.auth.typoed_key", "Unknown auth key")

    def test_context_file_must_be_string(self):
        cfg = {"scanners": {"zap": {"auth": {"context_file": 42}}}}
        errs = _errors(cfg)
        assert _has_at(errs, "scanners.zap.auth.context_file", "string")

    def test_auth_password_env_invalid_identifier_errors(self):
        cfg = {"scanners": {"zap": {"auth": {
            "password_env": "HAS-DASH",
        }}}}
        errs = _errors(cfg)
        assert _has_at(errs, "scanners.zap.auth.password_env", "not a valid")

    def test_auth_must_be_mapping(self):
        cfg = {"scanners": {"zap": {"auth": "not-a-dict"}}}
        errs = _errors(cfg)
        assert _has_at(errs, "scanners.zap.auth", "Must be a mapping")


# --------------------------------------------------------------------- #
# ZAP tuning keys                                                       #
# --------------------------------------------------------------------- #


class TestZapTuningKeys:
    def test_all_new_keys_accepted(self):
        cfg = {"scanners": {"zap": {
            "target_url": "https://app.example.com",
            "api_spec": "https://app.example.com/openapi.json",
            "rules_file": ".zap/rules.tsv",
            "cmd_options": ["-z", "-config view.locale=en_GB"],
            "max_duration_minutes": 30,
            "healthcheck_url": "https://app.example.com/healthz",
            "app_image_ref": "ghcr.io/myorg/app:latest",
            "app_ports": "8080:8080",
        }}}
        assert _errors(cfg) == []
        assert _warnings(cfg) == []

    def test_cmd_options_must_be_list_of_strings(self):
        cfg = {"scanners": {"zap": {"cmd_options": "not-a-list"}}}
        errs = _errors(cfg)
        assert _has_at(errs, "scanners.zap.cmd_options", "list of strings")

    def test_cmd_options_with_non_string_entry_errors(self):
        cfg = {"scanners": {"zap": {"cmd_options": ["-z", 42]}}}
        errs = _errors(cfg)
        assert _has_at(errs, "scanners.zap.cmd_options", "list of strings")

    def test_max_duration_minutes_must_be_positive_int(self):
        cfg = {"scanners": {"zap": {"max_duration_minutes": -5}}}
        errs = _errors(cfg)
        assert _has_at(errs, "scanners.zap.max_duration_minutes", "positive integer")

    def test_max_duration_minutes_rejects_bool(self):
        # bool is an int subclass; we explicitly reject it.
        cfg = {"scanners": {"zap": {"max_duration_minutes": True}}}
        errs = _errors(cfg)
        assert _has_at(errs, "scanners.zap.max_duration_minutes", "positive integer")


# --------------------------------------------------------------------- #
# Container scanner — same credential contract, no surface change      #
# --------------------------------------------------------------------- #


class TestContainerCredentialParity:
    def test_container_accepts_env_ref_form(self):
        cfg = {"scanners": {"container": {
            "image_ref": "myapp:latest",
            "registry_username_env": "REGISTRY_USER",
            "registry_password_env": "REGISTRY_TOKEN",
        }}}
        assert _errors(cfg) == []

    def test_container_existing_literal_form_still_works(self):
        # Back-compat: literal values still accepted without surface change.
        cfg = {"scanners": {"container": {
            "image_ref": "myapp:latest",
            "registry_username": "user",
            "registry_password": "literal-pass",
        }}}
        assert _errors(cfg) == []


# --------------------------------------------------------------------- #
# Registry-driven validation — issue #168-F                              #
# --------------------------------------------------------------------- #


class TestUnknownScannerName:
    """Unknown scanner names should be rejected at validate time rather
    than silently accepted with only a downstream 'unknown keys' warning."""

    def test_unknown_scanner_errors(self):
        errs = _errors({"scanners": {"definitely-not-a-scanner": {"enabled": True}}})
        assert _has_at(errs, "scanners.definitely-not-a-scanner", "Unknown scanner")

    def test_known_scanner_passes(self):
        # bandit is in the SCANNER_REGISTRY built-ins.
        assert _errors({"scanners": {"bandit": {"enabled": True}}}) == []


class TestReporterRegistrySync:
    """``reporting.formats`` accepts everything registered under the
    ``argus.reporters`` group, not just the four-format hardcoded set
    the validator used pre-1.0.2."""

    def test_github_gitlab_junit_accepted(self):
        cfg = {"reporting": {"formats": ["github", "gitlab", "junit"]}}
        assert _errors(cfg) == []

    def test_unknown_format_still_errors(self):
        cfg = {"reporting": {"formats": ["nonsense"]}}
        errs = _errors(cfg)
        assert _has_at(errs, "reporting.formats[0]", "Invalid format")
