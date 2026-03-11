#!/usr/bin/env python3
"""
Unit tests for scanner-osv/scripts/parse_results.py
Tests OSV-Scanner JSON parsing and severity extraction.
"""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
PARSER_SCRIPT = SCRIPTS_DIR / "parse_results.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scanner-outputs" / "osv"

spec = importlib.util.spec_from_file_location("osv_parse_results", PARSER_SCRIPT)
parse_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_mod)


class TestGetCounts:
    """Test get_counts function."""

    def test_zero_findings(self):
        fixture = FIXTURES_DIR / "results-zero-findings.json"
        result = parse_mod.get_counts(str(fixture))
        assert result == {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

    def test_with_findings(self):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        result = parse_mod.get_counts(str(fixture))
        assert result["critical"] == 1
        assert result["high"] == 1
        assert result["medium"] == 1
        assert result["low"] == 1
        assert result["total"] == 4

    def test_missing_file(self, tmp_path):
        result = parse_mod.get_counts(str(tmp_path / "nonexistent.json"))
        assert result["total"] == 0

    def test_empty_file(self, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text("")
        result = parse_mod.get_counts(str(empty))
        assert result["total"] == 0

    def test_malformed_json(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{invalid json")
        result = parse_mod.get_counts(str(bad))
        assert result["total"] == 0

    def test_missing_results_key(self, tmp_path):
        no_results = tmp_path / "no-results.json"
        no_results.write_text(json.dumps({"other": "data"}))
        result = parse_mod.get_counts(str(no_results))
        assert result["total"] == 0

    def test_results_not_a_list(self, tmp_path):
        bad_type = tmp_path / "bad-type.json"
        bad_type.write_text(json.dumps({"results": "not-a-list"}))
        result = parse_mod.get_counts(str(bad_type))
        assert result["total"] == 0

    def test_deduplication(self, tmp_path):
        """Same vuln ID across multiple packages should be counted once."""
        data = {
            "results": [
                {
                    "source": {"path": "a.lock", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "pkg-a", "version": "1.0", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-dupe-1234",
                                    "database_specific": {"severity": "HIGH"},
                                }
                            ],
                        },
                        {
                            "package": {"name": "pkg-b", "version": "2.0", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-dupe-1234",
                                    "database_specific": {"severity": "HIGH"},
                                }
                            ],
                        },
                    ],
                }
            ]
        }
        f = tmp_path / "dedup.json"
        f.write_text(json.dumps(data))
        result = parse_mod.get_counts(str(f))
        assert result["high"] == 1
        assert result["total"] == 1

    def test_packages_not_a_list(self, tmp_path):
        data = {"results": [{"source": {}, "packages": "invalid"}]}
        f = tmp_path / "bad-packages.json"
        f.write_text(json.dumps(data))
        result = parse_mod.get_counts(str(f))
        assert result["total"] == 0

    def test_vulnerabilities_not_a_list(self, tmp_path):
        data = {
            "results": [
                {
                    "source": {},
                    "packages": [
                        {
                            "package": {"name": "x", "version": "1", "ecosystem": "npm"},
                            "vulnerabilities": "not-a-list",
                        }
                    ],
                }
            ]
        }
        f = tmp_path / "bad-vulns.json"
        f.write_text(json.dumps(data))
        result = parse_mod.get_counts(str(f))
        assert result["total"] == 0


class TestResolveSeverity:
    """Test severity resolution from OSV records."""

    def test_database_specific_top_level(self):
        vuln = {"database_specific": {"severity": "HIGH"}}
        assert parse_mod.resolve_severity(vuln) == "HIGH"

    def test_database_specific_affected(self):
        vuln = {
            "affected": [
                {"database_specific": {"severity": "CRITICAL"}}
            ]
        }
        assert parse_mod.resolve_severity(vuln) == "CRITICAL"

    def test_moderate_maps_to_medium(self):
        vuln = {"database_specific": {"severity": "MODERATE"}}
        assert parse_mod.resolve_severity(vuln) == "MEDIUM"

    def test_cvss_vector_fallback(self):
        vuln = {
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ]
        }
        result = parse_mod.resolve_severity(vuln)
        assert result in ("CRITICAL", "HIGH")

    def test_no_severity_defaults_to_low(self):
        vuln = {"id": "GHSA-xxxx"}
        assert parse_mod.resolve_severity(vuln) == "LOW"

    def test_null_database_specific(self):
        vuln = {"database_specific": None}
        assert parse_mod.resolve_severity(vuln) == "LOW"

    def test_empty_affected_list(self):
        vuln = {"affected": []}
        assert parse_mod.resolve_severity(vuln) == "LOW"

    def test_case_insensitive_severity(self):
        vuln = {"database_specific": {"severity": "critical"}}
        assert parse_mod.resolve_severity(vuln) == "CRITICAL"


class TestGetVulnerabilities:
    """Test get_vulnerabilities function."""

    def test_zero_findings(self):
        fixture = FIXTURES_DIR / "results-zero-findings.json"
        result = parse_mod.get_vulnerabilities(str(fixture))
        assert result == []

    def test_with_findings(self):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        result = parse_mod.get_vulnerabilities(str(fixture))
        assert len(result) == 4
        assert result[0]["severity"] == "CRITICAL"
        assert result[0]["package"] == "lodash"
        assert result[0]["fixed_version"] == "4.17.21"

    def test_sorted_by_severity(self):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        result = parse_mod.get_vulnerabilities(str(fixture))
        severities = [v["severity"] for v in result]
        expected_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for i in range(len(severities) - 1):
            assert expected_order[severities[i]] <= expected_order[severities[i + 1]]

    def test_missing_file(self, tmp_path):
        result = parse_mod.get_vulnerabilities(str(tmp_path / "nope.json"))
        assert result == []

    def test_deduplication(self, tmp_path):
        data = {
            "results": [
                {
                    "source": {"path": "a.lock", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "x", "version": "1.0", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {"id": "GHSA-1", "database_specific": {"severity": "HIGH"}, "summary": "test"}
                            ],
                        },
                        {
                            "package": {"name": "y", "version": "2.0", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {"id": "GHSA-1", "database_specific": {"severity": "HIGH"}, "summary": "test"}
                            ],
                        },
                    ],
                }
            ]
        }
        f = tmp_path / "dedup.json"
        f.write_text(json.dumps(data))
        result = parse_mod.get_vulnerabilities(str(f))
        assert len(result) == 1


class TestCLI:
    """Test CLI invocation."""

    def test_counts_command(self):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        result = subprocess.run(
            [sys.executable, str(PARSER_SCRIPT), "counts", str(fixture)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        parts = result.stdout.strip().split()
        assert len(parts) == 4
        assert all(p.isdigit() for p in parts)

    def test_vulnerabilities_command(self):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        result = subprocess.run(
            [sys.executable, str(PARSER_SCRIPT), "vulnerabilities", str(fixture)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) > 0

    def test_zero_findings_cli(self):
        fixture = FIXTURES_DIR / "results-zero-findings.json"
        result = subprocess.run(
            [sys.executable, str(PARSER_SCRIPT), "counts", str(fixture)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == "0 0 0 0"


class TestCVSSVectorParsing:
    """Test CVSS vector score extraction edge cases."""

    def test_invalid_vector_prefix(self):
        assert parse_mod._cvss_score_from_vector("not-a-vector") is None

    def test_empty_vector(self):
        assert parse_mod._cvss_score_from_vector("") is None

    def test_none_vector(self):
        assert parse_mod._cvss_score_from_vector(None) is None

    def test_low_impact_vector(self):
        # AV:L (not network), AC:H (high complexity), PR:H (high priv)
        score = parse_mod._cvss_score_from_vector(
            "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:L"
        )
        assert score is not None
        assert score < 7.0  # Should be low/medium

    def test_high_impact_vector(self):
        score = parse_mod._cvss_score_from_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        assert score is not None
        assert score >= 9.0


class TestScoreToSeverity:
    """Test CVSS score to severity label mapping."""

    def test_critical(self):
        assert parse_mod._score_to_severity(9.0) == "CRITICAL"
        assert parse_mod._score_to_severity(10.0) == "CRITICAL"

    def test_high(self):
        assert parse_mod._score_to_severity(7.0) == "HIGH"
        assert parse_mod._score_to_severity(8.9) == "HIGH"

    def test_medium(self):
        assert parse_mod._score_to_severity(4.0) == "MEDIUM"
        assert parse_mod._score_to_severity(6.9) == "MEDIUM"

    def test_low(self):
        assert parse_mod._score_to_severity(3.9) == "LOW"
        assert parse_mod._score_to_severity(0.0) == "LOW"


class TestExtractFixedVersion:
    """Test fixed version extraction from affected ranges."""

    def test_with_fixed_event(self):
        vuln = {
            "affected": [
                {
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "ranges": [
                        {"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
                    ],
                }
            ]
        }
        assert parse_mod._extract_fixed_version(vuln, "npm", "lodash") == "4.17.21"

    def test_no_affected(self):
        assert parse_mod._extract_fixed_version({}, "npm", "pkg") == "N/A"

    def test_affected_not_list(self):
        assert parse_mod._extract_fixed_version(
            {"affected": "invalid"}, "npm", "pkg"
        ) == "N/A"

    def test_ranges_not_list(self):
        vuln = {
            "affected": [
                {"package": {"name": "pkg"}, "ranges": "invalid"}
            ]
        }
        assert parse_mod._extract_fixed_version(vuln, "npm", "pkg") == "N/A"

    def test_events_not_list(self):
        vuln = {
            "affected": [
                {"package": {"name": "pkg"}, "ranges": [{"events": "invalid"}]}
            ]
        }
        assert parse_mod._extract_fixed_version(vuln, "npm", "pkg") == "N/A"

    def test_no_fixed_event(self):
        vuln = {
            "affected": [
                {
                    "package": {"name": "pkg"},
                    "ranges": [{"events": [{"introduced": "0"}]}],
                }
            ]
        }
        assert parse_mod._extract_fixed_version(vuln, "npm", "pkg") == "N/A"

    def test_wrong_package_name(self):
        vuln = {
            "affected": [
                {
                    "package": {"name": "other-pkg"},
                    "ranges": [{"events": [{"fixed": "1.0"}]}],
                }
            ]
        }
        assert parse_mod._extract_fixed_version(vuln, "npm", "pkg") == "N/A"


class TestGetVulnerabilitiesEdgeCases:
    """Test get_vulnerabilities edge cases."""

    def test_results_not_list(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text(json.dumps({"results": "not-a-list"}))
        assert parse_mod.get_vulnerabilities(str(f)) == []

    def test_packages_not_list(self, tmp_path):
        data = {"results": [{"source": {}, "packages": "invalid"}]}
        f = tmp_path / "bad.json"
        f.write_text(json.dumps(data))
        assert parse_mod.get_vulnerabilities(str(f)) == []

    def test_vulns_not_list(self, tmp_path):
        data = {
            "results": [
                {
                    "source": {"path": "a.lock"},
                    "packages": [
                        {
                            "package": {"name": "x", "version": "1", "ecosystem": "npm"},
                            "vulnerabilities": "not-a-list",
                        }
                    ],
                }
            ]
        }
        f = tmp_path / "bad.json"
        f.write_text(json.dumps(data))
        assert parse_mod.get_vulnerabilities(str(f)) == []

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text("")
        assert parse_mod.get_vulnerabilities(str(f)) == []


class TestMainInProcess:
    """Test main() CLI entry point in-process for coverage."""

    def test_counts_main(self, tmp_path, monkeypatch):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        monkeypatch.setattr(
            "sys.argv", ["parse_results.py", "counts", str(fixture)]
        )
        parse_mod.main()

    def test_vulnerabilities_main(self, tmp_path, monkeypatch):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        monkeypatch.setattr(
            "sys.argv", ["parse_results.py", "vulnerabilities", str(fixture)]
        )
        parse_mod.main()
