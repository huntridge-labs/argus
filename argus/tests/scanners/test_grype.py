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
    def test_scan_without_sbom_raises_precondition_error(self):
        """Issue #168-I: missing --sbom is a precondition failure, not a
        silently-passed scan. Raising lets the engine mark the scanner
        ``execution_failed`` so CI gating treats it as "didn't run"
        rather than "passed with 0 findings"."""
        import pytest
        from argus.core.engine import ScannerPreconditionError
        with pytest.raises(ScannerPreconditionError, match="sbom_path"):
            GrypeScanner().scan(path=".", config={})


class TestGrypeUnknownSource:
    """Grype surfaces a warning when it can't identify the scan subject."""

    def _write(self, path, matches, source_target):
        import json
        path.write_text(json.dumps({
            "matches": matches,
            "source": {"target": source_target, "type": "sbom"},
            "descriptor": {"name": "grype"},
        }))

    def test_returns_plain_list_when_source_is_known(self, tmp_path):
        f = tmp_path / "r.json"
        self._write(f, [], source_target="container-a")
        parsed = GrypeScanner().parse_results(f)
        # Known source + no matches = clean list, no warning extras
        assert parsed == []

    def test_attaches_warning_when_source_unknown_and_empty(self, tmp_path):
        f = tmp_path / "r.json"
        self._write(f, [], source_target="unknown")
        parsed = GrypeScanner().parse_results(f)
        # Tuple shape signals engine to merge extra metadata
        assert isinstance(parsed, tuple)
        findings, extra = parsed
        assert findings == []
        assert "source.target=unknown" in extra["warning"]
        assert "0 findings does not mean clean" in extra["warning"]

    def test_no_warning_when_source_unknown_but_findings_exist(self, tmp_path):
        # If Grype *did* match something despite "unknown" source we
        # don't muddy the waters with a false warning.
        f = tmp_path / "r.json"
        match = {
            "vulnerability": {
                "id": "CVE-2026-1", "severity": "High",
                "description": "test", "fix": {"versions": ["1.1"]},
            },
            "artifact": {"name": "x", "version": "1.0"},
        }
        self._write(f, [match], source_target="unknown")
        parsed = GrypeScanner().parse_results(f)
        assert isinstance(parsed, list)  # plain list, no warning extras
        assert len(parsed) == 1
