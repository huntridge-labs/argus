"""Tests for argus.scanners.gosec — GosecScanner."""

import json

from argus.core.models import Severity
from argus.core.redact import REDACTED_PLACEHOLDER
from argus.scanners.gosec import GosecScanner


class TestGosecParseResults:
    """Test GosecScanner.parse_results with fixture data."""

    def test_parse_results_with_findings(self, fixtures_dir):
        scanner = GosecScanner()
        path = fixtures_dir / "gosec" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 4

        severities = [f.severity for f in findings]
        assert severities.count(Severity.HIGH) == 1
        assert severities.count(Severity.MEDIUM) == 2
        assert severities.count(Severity.LOW) == 1

    def test_parse_results_zero_findings(self, fixtures_dir):
        scanner = GosecScanner()
        path = fixtures_dir / "gosec" / "results-zero-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = GosecScanner()
        path = fixtures_dir / "gosec" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        first = findings[0]
        assert first.id == "G201"
        assert first.severity == Severity.HIGH
        assert first.scanner == "gosec"
        assert first.cwe == "CWE-89"
        assert "db.go:42" in first.location
        assert first.metadata["confidence"] == "HIGH"
        assert first.metadata["rule_id"] == "G201"

    def test_severity_mapping(self, fixtures_dir):
        scanner = GosecScanner()
        path = fixtures_dir / "gosec" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        by_id = {f.id: f for f in findings}
        assert by_id["G201"].severity == Severity.HIGH
        assert by_id["G304"].severity == Severity.MEDIUM
        assert by_id["G104"].severity == Severity.LOW


class TestGosecScannerMeta:
    """Test GosecScanner metadata methods."""

    def test_name(self):
        assert GosecScanner().name == "gosec"

    def test_install_command(self):
        cmd = GosecScanner().install_command()
        assert cmd is not None
        assert "gosec" in cmd

    def test_languages(self):
        assert GosecScanner().languages == ["go"]

    def test_build_args_recurses_workspace(self):
        from argus.core.scanner_template import ScanPaths

        scanner = GosecScanner()
        paths = ScanPaths(workspace="/workspace", output="/tmp/out.json")
        args = scanner.build_args(paths, {})

        assert args[0] == "gosec"
        assert "-fmt=json" in args
        assert "-out=/tmp/out.json" in args
        assert "/workspace/..." in args

    def test_build_args_routes_path_excludes_to_exclude_dir(self):
        # Regression: the engine injects a comma-joined PATH list into
        # config["exclude"]. gosec's -exclude is for RULE IDs and rejects
        # a path list outright (exit 2), so paths MUST go to -exclude-dir,
        # one repeatable flag per pattern. This is the bug that made gosec
        # silently scan nothing.
        from argus.core.scanner_template import ScanPaths

        scanner = GosecScanner()
        paths = ScanPaths(workspace="/workspace", output="/tmp/out.json")
        args = scanner.build_args(paths, {"exclude": "node_modules,.git,*.egg-info"})

        assert "-exclude" not in args, "path list must not go to -exclude (rule IDs)"
        # One -exclude-dir per pattern, in order.
        dir_values = [args[i + 1] for i, a in enumerate(args) if a == "-exclude-dir"]
        assert dir_values == ["node_modules", "\\.git", ".*\\.egg\\-info"]

    def test_glob_to_regex_translates_wildcards_safely(self):
        # *.egg-info must become a compilable regex (gosec compiles each
        # -exclude-dir value); a bare "*" is an invalid regex quantifier.
        import re as _re
        from argus.scanners.gosec import _glob_to_regex

        out = _glob_to_regex("*.egg-info")
        assert out == ".*\\.egg\\-info"
        _re.compile(out)  # must not raise


class TestGosecRedaction:
    """gosec's G101 (hardcoded-credentials) rule puts the offending Go
    source line into ``code`` and interpolates the literal into
    ``details``. Both leak the secret to every downstream consumer —
    terminal output, JSON exports, Markdown / SARIF reports, and (most
    acutely) the MCP server's AI-assistant context.

    These tests assert the parser strips the literal for G101 and leaves
    other rule IDs' code excerpts intact so the bulk of gosec's triage
    value (code context on real findings) is preserved.
    """

    # The G101 entry in the fixture has this literal value. Deliberately
    # distinctive so a substring leak check over the serialized Finding
    # can't be fooled by overlap with gosec's own rule taxonomy.
    _G101_LITERAL = "s3cr3t-pw-XYZ123"

    def test_g101_details_redacts_literal(self, fixtures_dir):
        scanner = GosecScanner()
        path = fixtures_dir / "gosec" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        g101 = [f for f in findings if f.id == "G101"]
        assert g101, "fixture is expected to include a G101 finding"
        for f in g101:
            assert self._G101_LITERAL not in f.description
            assert REDACTED_PLACEHOLDER in f.description

    def test_g101_code_excerpt_replaced(self, fixtures_dir):
        scanner = GosecScanner()
        path = fixtures_dir / "gosec" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        for f in (x for x in findings if x.id == "G101"):
            assert f.metadata["code"] == REDACTED_PLACEHOLDER

    def test_g101_literal_never_appears_in_serialized_finding(self, fixtures_dir):
        # Belt-and-suspenders: dump the whole Finding to JSON and assert
        # the literal isn't present anywhere — catches a future field we
        # forgot to redact.
        scanner = GosecScanner()
        path = fixtures_dir / "gosec" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        for f in (x for x in findings if x.id == "G101"):
            blob = json.dumps(f.to_dict())
            assert self._G101_LITERAL not in blob, (
                f"G101 literal {self._G101_LITERAL!r} leaked into "
                "Finding JSON — redaction regressed"
            )

    def test_non_secret_rules_keep_their_code_excerpt(self, fixtures_dir):
        # G201 / G304 / G104 are NOT credential rules — their code
        # excerpts are valuable triage signal and should pass through
        # unchanged. Without this guard a future "redact everything"
        # change would silently strip legitimate context from every
        # other gosec rule.
        scanner = GosecScanner()
        path = fixtures_dir / "gosec" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        non_secret = [f for f in findings if f.id != "G101"]
        assert non_secret, "fixture is expected to include non-secret rules"
        for f in non_secret:
            assert f.metadata["code"] != REDACTED_PLACEHOLDER
            assert REDACTED_PLACEHOLDER not in f.description
