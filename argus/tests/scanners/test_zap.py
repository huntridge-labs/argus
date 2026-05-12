"""Tests for argus.scanners.zap — ZapScanner."""

import pytest

from argus.core.models import Severity
from argus.scanners.zap import ZapScanner


class TestZapParseResults:
    """Test ZapScanner.parse_results with fixture data."""

    def test_parse_baseline_scan(self, fixtures_dir):
        scanner = ZapScanner()
        path = fixtures_dir / "zap" / "results-baseline-scan.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 3

        severities = [f.severity for f in findings]
        # riskcode 1 -> LOW (x2), riskcode 2 -> MEDIUM (x1)
        assert severities.count(Severity.HIGH) == 0
        assert severities.count(Severity.MEDIUM) == 1
        assert severities.count(Severity.LOW) == 2

    def test_parse_zero_findings(self, fixtures_dir):
        scanner = ZapScanner()
        path = fixtures_dir / "zap" / "results-zero-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = ZapScanner()
        path = fixtures_dir / "zap" / "results-baseline-scan.json"
        findings = scanner.parse_results(path)

        # Medium finding is Cross-Domain Misconfiguration
        medium = [f for f in findings if f.severity == Severity.MEDIUM][0]
        assert medium.id == "10098"
        assert medium.scanner == "zap"
        assert medium.cwe == "CWE-264"
        assert medium.location is not None
        assert "instance_count" in medium.metadata

        # LOW findings should have CWE set
        low_findings = [f for f in findings if f.severity == Severity.LOW]
        for finding in low_findings:
            assert finding.cwe is not None


class TestZapScannerMeta:
    """Test ZapScanner metadata methods."""

    def test_name(self):
        assert ZapScanner().name == "zap"

    def test_install_command(self):
        cmd = ZapScanner().install_command()
        assert cmd is not None


class TestZapContainerArgs:
    """Container-arg construction from argus.yml passthrough config (ADR-024)."""

    def test_baseline_default(self):
        args = ZapScanner().container_args({"target_url": "http://app:8080"})

        assert args[0] == "zap-baseline.py"
        assert "-t" in args and "http://app:8080" in args
        assert "-J" in args and "/output/results.json" in args

    def test_full_scan_type(self):
        args = ZapScanner().container_args({
            "target_url": "http://app:8080",
            "scan_type": "full",
        })
        assert args[0] == "zap-full-scan.py"

    def test_api_spec_switches_to_api_scan(self):
        args = ZapScanner().container_args({
            "target_url": "http://app:8080",
            "api_spec": "http://app:8080/openapi.json",
        })
        assert args[0] == "zap-api-scan.py"
        # api_spec is what gets scanned, not target_url
        assert "http://app:8080/openapi.json" in args
        assert "-f" in args and "openapi" in args

    def test_explicit_scan_type_api(self):
        args = ZapScanner().container_args({
            "target_url": "http://app:8080",
            "scan_type": "api",
        })
        assert args[0] == "zap-api-scan.py"

    def test_rules_file_uses_container_path(self):
        args = ZapScanner().container_args({
            "target_url": "http://app",
            "rules_file": "/host/path/rules.tsv",
        })
        assert "-c" in args
        # ``-c`` value is the container-side path, not the host path
        ci = args.index("-c")
        assert args[ci + 1] == "/zap/wrk/rules.tsv"

    def test_context_file_uses_container_path(self):
        args = ZapScanner().container_args({
            "target_url": "http://app",
            "auth": {"context_file": "/host/.zap/ctx.xml"},
        })
        assert "-n" in args
        ni = args.index("-n")
        assert args[ni + 1] == "/zap/wrk/context.xml"

    def test_max_duration_minutes(self):
        args = ZapScanner().container_args({
            "target_url": "http://app",
            "max_duration_minutes": 30,
        })
        assert "-T" in args
        ti = args.index("-T")
        assert args[ti + 1] == "30"

    def test_cmd_options_appended_verbatim(self):
        args = ZapScanner().container_args({
            "target_url": "http://app",
            "cmd_options": ["-z", "-config view.locale=en_GB"],
        })
        # ``cmd_options`` lands at the end, after all built-in flags
        assert args[-2:] == ["-z", "-config view.locale=en_GB"]


class TestZapContainerEnv:
    """Credential resolution and env-var passthrough into the container."""

    def test_no_credentials_returns_empty_dict(self):
        assert ZapScanner().container_env({"target_url": "http://app"}) == {}

    def test_registry_username_password_via_env_refs(self, monkeypatch):
        monkeypatch.setenv("REG_USER", "alice")
        monkeypatch.setenv("REG_TOKEN", "s3cret")
        env = ZapScanner().container_env({
            "registry_username_env": "REG_USER",
            "registry_password_env": "REG_TOKEN",
        })
        assert env["ZAP_REGISTRY_USERNAME"] == "alice"
        assert env["ZAP_REGISTRY_PASSWORD"] == "s3cret"

    def test_registry_literal_back_compat(self):
        env = ZapScanner().container_env({
            "registry_username": "alice",
            "registry_password": "literal",
        })
        assert env["ZAP_REGISTRY_USERNAME"] == "alice"
        assert env["ZAP_REGISTRY_PASSWORD"] == "literal"

    def test_web_app_auth_env_refs(self, monkeypatch):
        monkeypatch.setenv("APP_USER", "bob")
        monkeypatch.setenv("APP_PASS", "hunter2")
        env = ZapScanner().container_env({
            "auth": {
                "context_file": ".zap/ctx.xml",
                "username_env": "APP_USER",
                "password_env": "APP_PASS",
            },
        })
        assert env["ZAP_AUTH_USERNAME"] == "bob"
        assert env["ZAP_AUTH_PASSWORD"] == "hunter2"

    def test_unset_env_ref_does_not_inject_key(self, monkeypatch):
        monkeypatch.delenv("MISSING_VAR", raising=False)
        env = ZapScanner().container_env({
            "registry_password_env": "MISSING_VAR",
        })
        # Missing env var → resolve_secret returns None → not in env dict
        assert "ZAP_REGISTRY_PASSWORD" not in env

    def test_mixed_registry_and_auth(self, monkeypatch):
        monkeypatch.setenv("R_USER", "r-user")
        monkeypatch.setenv("A_PASS", "a-pass")
        env = ZapScanner().container_env({
            "registry_username_env": "R_USER",
            "auth": {"password_env": "A_PASS"},
        })
        assert env == {
            "ZAP_REGISTRY_USERNAME": "r-user",
            "ZAP_AUTH_PASSWORD": "a-pass",
        }


class TestZapContainerMounts:
    """Bind-mount tuples for rules and context files."""

    def test_no_files_returns_empty_list(self):
        assert ZapScanner().container_mounts({"target_url": "http://app"}) == []

    def test_rules_file_mount(self):
        mounts = ZapScanner().container_mounts({"rules_file": "/host/rules.tsv"})
        assert mounts == [("/host/rules.tsv", "/zap/wrk/rules.tsv")]

    def test_context_file_mount(self):
        mounts = ZapScanner().container_mounts({
            "auth": {"context_file": "/host/.zap/ctx.xml"},
        })
        assert mounts == [("/host/.zap/ctx.xml", "/zap/wrk/context.xml")]

    def test_both_files_mounted(self):
        mounts = ZapScanner().container_mounts({
            "rules_file": "/host/rules.tsv",
            "auth": {"context_file": "/host/ctx.xml"},
        })
        assert ("/host/rules.tsv", "/zap/wrk/rules.tsv") in mounts
        assert ("/host/ctx.xml", "/zap/wrk/context.xml") in mounts
        assert len(mounts) == 2


class TestZapLocalBackend:
    """Local-binary backend: warns when container-only knobs are set."""

    def test_warns_on_container_only_keys(self, caplog, tmp_path):
        # No zap-cli binary in test env → local path bails with error
        # *after* the warning is emitted.
        scanner = ZapScanner()
        import logging
        with caplog.at_level(logging.WARNING, logger="argus"):
            scanner.scan(
                path=str(tmp_path),
                config={
                    "target_url": "http://app:8080",
                    "rules_file": "/host/rules.tsv",
                    "max_duration_minutes": 30,
                },
            )
        msgs = [r.message for r in caplog.records]
        assert any("local-binary backend ignores" in m for m in msgs)
        assert any("rules_file" in m for m in msgs)
