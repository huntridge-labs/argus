"""Unit tests for argus.scanners.grype — standalone SBOM-mode scanner."""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from argus.core.models import Severity
from argus.scanners.grype import GrypeScanner


class TestGrypeCapabilities:
    def test_supports_sbom(self):
        assert GrypeScanner.supports_sbom is True

    def test_has_category_sca(self):
        assert GrypeScanner.category == "sca"

    def test_is_available_checks_path(self):
        scanner = GrypeScanner()
        with patch("argus.scanners.grype.shutil.which", return_value=None):
            assert scanner.is_available() is False
        with patch("argus.scanners.grype.shutil.which", return_value="/usr/bin/grype"):
            assert scanner.is_available() is True


class TestGrypeContainerArgs:
    def test_requires_sbom_path(self):
        with pytest.raises(RuntimeError, match="sbom_path"):
            GrypeScanner().container_args({})

    def test_uses_mount_path_when_provided(self):
        args = GrypeScanner().container_args({
            "sbom_path": "/host/sbom.json",
            "sbom_mount_path": "/sbom/sbom.json",
        })
        assert "sbom:/sbom/sbom.json" in args
        assert "--file" in args
        assert "/output/results.json" in args

    def test_falls_back_to_workspace_mount(self):
        args = GrypeScanner().container_args({"sbom_path": "/host/sbom.json"})
        # Default mount when not engine-provided uses /workspace/<basename>
        assert "sbom:/workspace/sbom.json" in args


class TestGrypeParseResults:
    def test_parses_matches(self, tmp_path):
        raw = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2026-12345",
                        "severity": "High",
                        "description": "Some vuln",
                        "fix": {"versions": ["1.2.3"]},
                    },
                    "artifact": {"name": "pkg", "version": "1.2.0"},
                },
            ],
        }
        f = tmp_path / "results.json"
        f.write_text(json.dumps(raw))

        findings = GrypeScanner().parse_results(f)
        assert len(findings) == 1
        assert findings[0].cve == "CVE-2026-12345"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].location == "pkg@1.2.0"
        assert findings[0].scanner == "grype"

    def test_handles_empty_matches(self, tmp_path):
        f = tmp_path / "results.json"
        f.write_text(json.dumps({"matches": []}))
        assert GrypeScanner().parse_results(f) == []

    def test_malformed_json_returns_empty(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{not json")
        assert GrypeScanner().parse_results(f) == []


class TestGrypeScanNoSbom:
    def test_scan_without_sbom_returns_error(self):
        result = GrypeScanner().scan(path=".", config={})
        assert result.findings == []
        assert "sbom_path" in result.metadata.get("error", "")
