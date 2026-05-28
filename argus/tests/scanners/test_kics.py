"""Tests for argus.scanners.kics — KICSScanner."""

import json

from argus.core.models import Severity
from argus.core.redact import REDACTED_PLACEHOLDER
from argus.core.scanner_template import ScanPaths
from argus.scanners.kics import KICSScanner


class TestKICSParseResults:
    """Test KICSScanner.parse_results with fixture data."""

    def test_parse_results_with_findings(self, fixtures_dir):
        scanner = KICSScanner()
        path = fixtures_dir / "kics" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 4

        severities = [f.severity for f in findings]
        assert severities.count(Severity.HIGH) == 1
        assert severities.count(Severity.MEDIUM) == 1
        assert severities.count(Severity.LOW) == 1
        assert severities.count(Severity.INFO) == 1

    def test_parse_results_zero_findings(self, fixtures_dir):
        scanner = KICSScanner()
        path = fixtures_dir / "kics" / "results-zero-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = KICSScanner()
        path = fixtures_dir / "kics" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        medium = [f for f in findings if f.severity == Severity.MEDIUM][0]
        assert medium.id == "63ec5b46-7c4a-4e3e-9b8f-3d2c8e1f0a11"
        assert "encryption" in medium.title.lower()
        assert medium.scanner == "kics"
        assert medium.cwe == "CWE-311"
        assert medium.location == "terraform/s3.tf:8"
        assert medium.metadata["platform"] == "Terraform"
        assert medium.metadata["category"] == "Encryption"

    def test_finding_without_cwe_has_none(self, fixtures_dir):
        scanner = KICSScanner()
        path = fixtures_dir / "kics" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        # The LOW (Kubernetes runAsNonRoot) query has no cwe in the fixture.
        low = [f for f in findings if f.severity == Severity.LOW][0]
        assert low.cwe is None


class TestKICSScannerMeta:
    """Test KICSScanner metadata methods."""

    def test_name(self):
        assert KICSScanner().name == "kics"

    def test_category(self):
        assert KICSScanner().category == "iac"

    def test_install_command(self):
        cmd = KICSScanner().install_command()
        assert cmd is not None
        assert "kics" in cmd

    def test_build_args_passes_output_directory(self):
        # KICS -o takes the output *directory*, not the results file.
        scanner = KICSScanner()
        paths = ScanPaths(workspace="/workspace", output="/output/results.json")
        args = scanner.build_args(paths, {})

        assert "scan" in args
        assert "/workspace" in args
        # -o is followed by the parent dir of the results file.
        out_idx = args.index("-o")
        assert args[out_idx + 1] == "/output"
        # JSON report format requested.
        fmt_idx = args.index("--report-formats")
        assert args[fmt_idx + 1] == "json"


class TestKICSRedaction:
    """KICS echoes the offending source snippet in each match's
    ``actual_value`` / ``expected_value`` / ``search_value``. For a
    secrets-class query (KICS ships "Passwords And Secrets" queries for
    Ansible, Dockerfile, K8s, etc.) that snippet IS the secret, leaking
    to every downstream consumer — terminal output, JSON / Markdown /
    SARIF exports, and the MCP server's AI-assistant context.

    These tests assert the parser strips every per-match value field so
    the literal never reaches a Finding, while the location + query name
    remain as triage signal.
    """

    # The HIGH "Generic Password" query in the fixture carries this
    # literal in both search_value and actual_value. Distinctive so a
    # substring leak-check over the serialized Finding can't be fooled
    # by overlap with KICS's own rule taxonomy.
    _SECRET_LITERAL = "s3cr3t-pw-KICS999"

    def test_match_value_fields_are_redacted(self, fixtures_dir):
        scanner = KICSScanner()
        path = fixtures_dir / "kics" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        secret = [
            f for f in findings
            if f.id == "487f4be7-3fd9-4506-a07a-eae252180c08"
        ]
        assert secret, "fixture is expected to include the secrets query"
        for f in secret:
            assert f.metadata["actual_value"] == REDACTED_PLACEHOLDER
            assert f.metadata["search_value"] == REDACTED_PLACEHOLDER
            assert f.metadata["expected_value"] == REDACTED_PLACEHOLDER

    def test_secret_literal_never_appears_in_serialized_finding(self, fixtures_dir):
        # Belt-and-suspenders: dump the whole Finding to JSON and assert
        # the literal isn't present anywhere — catches a future field we
        # forgot to redact.
        scanner = KICSScanner()
        path = fixtures_dir / "kics" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        for f in findings:
            blob = json.dumps(f.to_dict())
            assert self._SECRET_LITERAL not in blob, (
                f"KICS secret literal {self._SECRET_LITERAL!r} leaked into "
                "Finding JSON — redaction regressed"
            )
