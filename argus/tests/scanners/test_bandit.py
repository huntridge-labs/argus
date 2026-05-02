"""Tests for argus.scanners.bandit — BanditScanner."""

import json

import pytest

from argus.core.models import Severity
from argus.core.redact import REDACTED_PLACEHOLDER
from argus.scanners.bandit import BanditScanner


class TestBanditParseResults:
    """Test BanditScanner.parse_results with fixture data."""

    def test_parse_results_with_findings(self, fixtures_dir):
        scanner = BanditScanner()
        path = fixtures_dir / "bandit" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 6

        severities = [f.severity for f in findings]
        assert severities.count(Severity.HIGH) == 2
        assert severities.count(Severity.MEDIUM) == 3
        assert severities.count(Severity.LOW) == 1

    def test_parse_results_zero_findings(self, fixtures_dir):
        scanner = BanditScanner()
        path = fixtures_dir / "bandit" / "results-zero-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = BanditScanner()
        path = fixtures_dir / "bandit" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        first = findings[0]
        assert first.id == "B403"
        assert first.severity == Severity.HIGH
        assert first.scanner == "bandit"
        assert first.cwe == "CWE-502"
        assert "app.py:12" in first.location
        assert first.metadata["test_name"] == "blacklist"


class TestBanditScannerMeta:
    """Test BanditScanner metadata methods."""

    def test_name(self):
        assert BanditScanner().name == "bandit"

    def test_install_command(self):
        cmd = BanditScanner().install_command()
        assert cmd is not None
        assert "bandit" in cmd


class TestBanditRedaction:
    """Bandit's B105 / B106 / B107 (hardcoded-credential) tests
    interpolate the matched literal into ``issue_text`` and put the
    offending source line into ``code``. Both leak the secret to
    every consumer downstream — terminal output, JSON exports,
    Markdown / SARIF reports, and (most acutely) the MCP server's
    AI-assistant context.

    These tests assert the parser strips the literal for those test
    IDs and leaves other test IDs unchanged so the bulk of bandit's
    triage value (code excerpts on real findings) is preserved.
    """

    # The B105 entry in the fixture has this literal value.
    # Deliberately distinctive so a leak check via substring search
    # over the serialized Finding can't be fooled by overlap with
    # bandit's own rule-name taxonomy (``hardcoded_password_string``).
    _B105_LITERAL = "s3cr3t-pw-XYZ123"

    def test_b105_issue_text_redacts_literal(self, fixtures_dir):
        scanner = BanditScanner()
        path = fixtures_dir / "bandit" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        b105 = [f for f in findings if f.id == "B105"]
        assert b105, "fixture is expected to include a B105 finding"
        for f in b105:
            assert f"'{self._B105_LITERAL}'" not in f.description
            assert REDACTED_PLACEHOLDER in f.description

    def test_b105_code_excerpt_replaced(self, fixtures_dir):
        scanner = BanditScanner()
        path = fixtures_dir / "bandit" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        for f in (x for x in findings if x.id == "B105"):
            assert f.metadata["code"] == REDACTED_PLACEHOLDER

    def test_b105_literal_never_appears_in_serialized_finding(self, fixtures_dir):
        # Belt-and-suspenders: dump the whole Finding to JSON and
        # assert the literal isn't present anywhere — catches a
        # future field we forgot to redact.
        scanner = BanditScanner()
        path = fixtures_dir / "bandit" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        for f in (x for x in findings if x.id == "B105"):
            blob = json.dumps(f.to_dict())
            assert self._B105_LITERAL not in blob, (
                f"B105 literal {self._B105_LITERAL!r} leaked into "
                "Finding JSON — redaction regressed"
            )

    def test_non_secret_tests_keep_their_code_excerpt(self, fixtures_dir):
        # B403 / B605 / B101 etc. are NOT credential tests — their
        # code excerpts are valuable triage signal and should pass
        # through unchanged. Without this guard a future "redact
        # everything" change would silently strip legitimate context
        # from every other bandit rule.
        scanner = BanditScanner()
        path = fixtures_dir / "bandit" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        non_secret = [
            f for f in findings if f.id not in ("B105", "B106", "B107")
        ]
        assert non_secret, "fixture is expected to include non-secret tests"
        for f in non_secret:
            # The code field should be a real source excerpt, not
            # the placeholder, and the description should include
            # the original issue_text without redaction.
            assert f.metadata["code"] != REDACTED_PLACEHOLDER
            assert REDACTED_PLACEHOLDER not in f.description
