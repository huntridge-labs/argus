#!/usr/bin/env python3
"""
Unit tests for scanner-dependency-review/scripts/parse_results.py
Tests dependency-review-action output parsing.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
PARSER_SCRIPT = SCRIPTS_DIR / "parse_results.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scanner-outputs" / "dependency-review"

spec = importlib.util.spec_from_file_location("dep_review_parse_results", PARSER_SCRIPT)
parse_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_mod)


class TestParseVulnerableChanges:
    """Test parse_vulnerable_changes function."""

    def test_zero_findings(self):
        fixture = FIXTURES_DIR / "results-zero-findings.json"
        data = json.loads(fixture.read_text())
        result = parse_mod.parse_vulnerable_changes(json.dumps(data["vulnerable_changes"]))
        assert result["critical"] == 0
        assert result["total"] == 0
        assert result["vulnerabilities"] == []

    def test_with_findings(self):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        data = json.loads(fixture.read_text())
        result = parse_mod.parse_vulnerable_changes(json.dumps(data["vulnerable_changes"]))
        assert result["critical"] == 1
        assert result["high"] == 1
        assert result["medium"] == 1
        assert result["low"] == 0
        assert result["total"] == 3

    def test_vulnerability_details(self):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        data = json.loads(fixture.read_text())
        result = parse_mod.parse_vulnerable_changes(json.dumps(data["vulnerable_changes"]))
        vulns = result["vulnerabilities"]
        assert vulns[0]["severity"] == "CRITICAL"
        assert vulns[0]["package"] == "lodash"
        assert vulns[0]["advisory_id"] == "GHSA-jfh8-c2jp-5v3q"

    def test_sorted_by_severity(self):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        data = json.loads(fixture.read_text())
        result = parse_mod.parse_vulnerable_changes(json.dumps(data["vulnerable_changes"]))
        severities = [v["severity"] for v in result["vulnerabilities"]]
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for i in range(len(severities) - 1):
            assert order[severities[i]] <= order[severities[i + 1]]

    def test_empty_string(self):
        result = parse_mod.parse_vulnerable_changes("")
        assert result["total"] == 0

    def test_null_input(self):
        result = parse_mod.parse_vulnerable_changes(None)
        assert result["total"] == 0

    def test_malformed_json(self):
        result = parse_mod.parse_vulnerable_changes("{not json")
        assert result["total"] == 0

    def test_non_list_json(self):
        result = parse_mod.parse_vulnerable_changes('{"key": "value"}')
        assert result["total"] == 0

    def test_moderate_maps_to_medium(self):
        changes = [
            {
                "name": "pkg",
                "version": "1.0",
                "vulnerabilities": [{"severity": "moderate", "advisory_ghsa_id": "GHSA-test"}],
            }
        ]
        result = parse_mod.parse_vulnerable_changes(json.dumps(changes))
        assert result["medium"] == 1
        assert result["vulnerabilities"][0]["severity"] == "MEDIUM"

    def test_invalid_change_entries(self):
        changes = ["not-a-dict", None, {"name": "valid", "vulnerabilities": "not-a-list"}]
        result = parse_mod.parse_vulnerable_changes(json.dumps(changes))
        assert result["total"] == 0

    def test_invalid_vulnerability_entries(self):
        changes = [
            {
                "name": "pkg",
                "version": "1.0",
                "vulnerabilities": ["not-a-dict", None],
            }
        ]
        result = parse_mod.parse_vulnerable_changes(json.dumps(changes))
        assert result["total"] == 0


class TestParseLicenseChanges:
    """Test parse_license_changes function."""

    def test_zero_violations(self):
        result = parse_mod.parse_license_changes("[]")
        assert result["count"] == 0
        assert result["violations"] == []

    def test_with_violations(self):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        data = json.loads(fixture.read_text())
        result = parse_mod.parse_license_changes(json.dumps(data["invalid_license_changes"]))
        assert result["count"] == 1
        assert result["violations"][0]["package"] == "some-gpl-package"
        assert result["violations"][0]["license"] == "GPL-3.0"

    def test_empty_string(self):
        result = parse_mod.parse_license_changes("")
        assert result["count"] == 0

    def test_null_input(self):
        result = parse_mod.parse_license_changes(None)
        assert result["count"] == 0

    def test_malformed_json(self):
        result = parse_mod.parse_license_changes("{bad")
        assert result["count"] == 0

    def test_non_list_json(self):
        result = parse_mod.parse_license_changes('{"key": "value"}')
        assert result["count"] == 0

    def test_invalid_entries_skipped(self):
        changes = ["not-a-dict", {"name": "valid", "license": "MIT"}]
        result = parse_mod.parse_license_changes(json.dumps(changes))
        assert result["count"] == 1


class TestCLI:
    """Test CLI invocation."""

    def test_counts_command(self):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        data = json.loads(fixture.read_text())
        vuln_json = json.dumps(data["vulnerable_changes"])
        result = subprocess.run(
            [
                sys.executable, str(PARSER_SCRIPT),
                "counts",
                "--vulnerable-changes", vuln_json,
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        parts = result.stdout.strip().split()
        assert len(parts) == 4

    def test_licenses_command(self):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        data = json.loads(fixture.read_text())
        lic_json = json.dumps(data["invalid_license_changes"])
        result = subprocess.run(
            [
                sys.executable, str(PARSER_SCRIPT),
                "licenses",
                "--license-changes", lic_json,
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["count"] == 1

    def test_all_command(self):
        fixture = FIXTURES_DIR / "results-with-findings.json"
        data = json.loads(fixture.read_text())
        result = subprocess.run(
            [
                sys.executable, str(PARSER_SCRIPT),
                "all",
                "--vulnerable-changes", json.dumps(data["vulnerable_changes"]),
                "--license-changes", json.dumps(data["invalid_license_changes"]),
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert "vulnerability_counts" in output
        assert "license_violations" in output
