"""Unit tests for argus.scanners.trivy — standalone SBOM-mode scanner."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from argus.core.models import Severity
from argus.scanners.trivy import TrivyScanner


class TestTrivyCapabilities:
    def test_supports_sbom(self):
        assert TrivyScanner.supports_sbom is True

    def test_has_category_sca(self):
        assert TrivyScanner.category == "sca"

    def test_distinct_from_trivy_iac(self):
        # Name must not collide with trivy-iac; trivy is the SBOM/vuln
        # scanner, trivy-iac is the Terraform/K8s misconfig scanner.
        assert TrivyScanner.name == "trivy"


class TestTrivyContainerArgs:
    def test_requires_sbom_path(self):
        with pytest.raises(RuntimeError, match="sbom_path"):
            TrivyScanner().container_args({})

    def test_uses_mount_path_when_provided(self):
        args = TrivyScanner().container_args({
            "sbom_path": "/host/sbom.json",
            "sbom_mount_path": "/sbom/sbom.json",
        })
        assert args[0] == "sbom"
        assert "/sbom/sbom.json" in args
        assert "--format" in args
        assert "json" in args

    def test_falls_back_to_workspace_mount(self):
        args = TrivyScanner().container_args({"sbom_path": "/host/sbom.json"})
        assert "/workspace/sbom.json" in args


class TestTrivyParseResults:
    def test_parses_trivy_results(self, tmp_path):
        raw = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-9999",
                            "Severity": "CRITICAL",
                            "PkgName": "libfoo",
                            "InstalledVersion": "1.0.0",
                            "FixedVersion": "1.0.1",
                            "Title": "Remote code execution",
                            "Description": "...",
                        }
                    ],
                }
            ]
        }
        f = tmp_path / "results.json"
        f.write_text(json.dumps(raw))

        findings = TrivyScanner().parse_results(f)
        assert len(findings) == 1
        assert findings[0].cve == "CVE-2026-9999"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].location == "libfoo@1.0.0"
        assert findings[0].metadata["fixed_version"] == "1.0.1"

    def test_handles_no_vulnerabilities(self, tmp_path):
        f = tmp_path / "results.json"
        f.write_text(json.dumps({"Results": [{"Vulnerabilities": []}]}))
        assert TrivyScanner().parse_results(f) == []

    def test_malformed_json_returns_empty(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("oops")
        assert TrivyScanner().parse_results(f) == []


class TestTrivyScanNoSbom:
    def test_scan_without_sbom_raises_precondition_error(self):
        """Issue #168-I: missing --sbom is a precondition failure, not a
        silently-passed scan. Raising lets the engine mark the scanner
        ``execution_failed`` so CI gating treats it as "didn't run"
        rather than "passed with 0 findings"."""
        import pytest
        from argus.core.engine import ScannerPreconditionError
        with pytest.raises(ScannerPreconditionError, match="sbom_path"):
            TrivyScanner().scan(path=".", config={})
