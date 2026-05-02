"""Tests for argus.scanners.gitleaks — GitleaksScanner."""

import json

import pytest

from argus.core.models import Severity
from argus.core.redact import REDACTED_PLACEHOLDER
from argus.scanners.gitleaks import GitleaksScanner


# Raw secret values that appear in the gitleaks fixture. If any of
# these strings shows up in a Finding's serialized output, redaction
# regressed. Update this list when the fixture changes.
_FIXTURE_SECRETS = [
    "ghp_1234567890abcdefghijklmnopqrstuvwxyz12",
    "AKIAIOSFODNN7EXAMPLE",
]
# Per-finding committer email/name pairs — gitleaks's Author / Email
# fields. Stripped from the Finding for PII reasons.
_FIXTURE_AUTHOR_PII = ["developer@example.com"]


class TestGitleaksParseResults:
    """Test GitleaksScanner.parse_results with fixture data."""

    def test_parse_results_with_findings(self, fixtures_dir):
        scanner = GitleaksScanner()
        path = fixtures_dir / "gitleaks" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 3
        assert all(f.severity == Severity.HIGH for f in findings)

    def test_parse_results_zero_findings(self, fixtures_dir):
        scanner = GitleaksScanner()
        path = fixtures_dir / "gitleaks" / "results-zero-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = GitleaksScanner()
        path = fixtures_dir / "gitleaks" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        first = findings[0]
        assert first.id == "github-pat"
        assert first.severity == Severity.HIGH
        assert first.scanner == "gitleaks"
        assert "config.py:12" in first.location
        assert first.metadata["commit"] == "abc123def456"
        assert first.metadata["rule_id"] == "github-pat"


class TestGitleaksScannerMeta:
    """Test GitleaksScanner metadata methods."""

    def test_name(self):
        assert GitleaksScanner().name == "gitleaks"

    def test_install_command(self):
        cmd = GitleaksScanner().install_command()
        assert cmd is not None


class TestGitleaksRedaction:
    """Argus's security commitment: a raw secret value detected by
    gitleaks NEVER lives past the parser. Every consumer downstream
    (terminal reporter, JSON / Markdown / SARIF exports, the MCP
    server's tool responses, the AI assistant's context window)
    must see the redaction placeholder instead.

    These tests load the gitleaks fixture, build Findings, and
    assert against the *fully serialized* JSON dump — not against
    individual fields — because that's what every consumer sees.
    A raw secret hiding in a metadata field we forgot about would
    still pass a per-field check; checking the JSON catches it.
    """

    def test_raw_secret_strings_never_appear_in_serialized_finding(self, fixtures_dir):
        scanner = GitleaksScanner()
        path = fixtures_dir / "gitleaks" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        for f in findings:
            blob = json.dumps(f.to_dict())
            for secret in _FIXTURE_SECRETS:
                assert secret not in blob, (
                    f"raw secret {secret!r} leaked into Finding JSON for "
                    f"rule {f.id} — redaction regressed"
                )

    def test_committer_pii_never_appears_in_serialized_finding(self, fixtures_dir):
        # gitleaks's Author / Email fields are PII (developer's
        # corporate email). The MCP path is the most acute leak —
        # we don't want a developer's email shipped to a third-party
        # LLM API just because gitleaks found a secret.
        scanner = GitleaksScanner()
        path = fixtures_dir / "gitleaks" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        for f in findings:
            blob = json.dumps(f.to_dict())
            for pii in _FIXTURE_AUTHOR_PII:
                assert pii not in blob, (
                    f"committer PII {pii!r} leaked into Finding JSON for "
                    f"rule {f.id}"
                )

    def test_match_field_replaced_with_placeholder(self, fixtures_dir):
        scanner = GitleaksScanner()
        path = fixtures_dir / "gitleaks" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        for f in findings:
            assert f.metadata["match"] == REDACTED_PLACEHOLDER

    def test_match_length_preserved_for_diagnostic_use(self, fixtures_dir):
        # Length is the rare diagnostic signal we DO keep — useful
        # for distinguishing two adjacent rule matches. Any positive
        # integer here means the parser saw a real value at the
        # source and substituted the placeholder; zero would mean
        # the upstream JSON was missing the field entirely.
        scanner = GitleaksScanner()
        path = fixtures_dir / "gitleaks" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        # github-pat fixture's Match is 42 chars
        # ("ghp_" + 38-char body); AWS access key fixture is 20.
        first = findings[0]
        assert first.metadata["match_length"] == 42

    def test_safe_fields_kept(self, fixtures_dir):
        # Commit SHA, rule ID, and fingerprint are public-safe and
        # genuinely useful for triage. Verify they survive the
        # redaction pass.
        scanner = GitleaksScanner()
        path = fixtures_dir / "gitleaks" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        first = findings[0]
        assert first.metadata["commit"] == "abc123def456"
        assert first.metadata["rule_id"] == "github-pat"
        assert first.metadata["fingerprint"]    # non-empty
