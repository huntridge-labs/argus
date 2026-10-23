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

        findings, _coverage = GrypeScanner().parse_results(f)
        assert len(findings) == 1
        assert findings[0].cve == "CVE-2026-12345"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].location == "pkg@1.2.0"
        assert findings[0].scanner == "grype"

    def test_handles_empty_matches(self, tmp_path):
        f = tmp_path / "results.json"
        f.write_text(json.dumps({"matches": []}))
        findings, _coverage = GrypeScanner().parse_results(f)
        assert findings == []

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

    def test_no_warning_when_source_is_known(self, tmp_path):
        f = tmp_path / "r.json"
        self._write(f, [], source_target="container-a")
        findings, extra = GrypeScanner().parse_results(f)
        # Known source + no matches = no warning; only the coverage keys
        assert findings == []
        assert "warning" not in extra

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
        findings, extra = GrypeScanner().parse_results(f)
        assert "warning" not in extra
        assert len(findings) == 1


class TestGrypeCoverageMetadata:
    """parse_results reports whether grype evaluated the OS packages (#492)."""

    def test_recognized_distro(self, tmp_path):
        f = tmp_path / "r.json"
        f.write_text(json.dumps({
            "matches": [],
            "distro": {"name": "amazonlinux", "version": "2023"},
        }))
        _, extra = GrypeScanner().parse_results(f)
        assert extra["os_packages_evaluated"] is True
        assert extra["matcher_os"] == "amazonlinux 2023"

    def test_unrecognized_distro(self, tmp_path):
        f = tmp_path / "r.json"
        f.write_text(json.dumps({
            "matches": [],
            "distro": {"name": "amazon", "version": "2023 (Amazon Linux)"},
        }))
        _, extra = GrypeScanner().parse_results(f)
        assert extra["os_packages_evaluated"] is False


class TestGrypeLocalScan:
    def test_local_scan_unpacks_parse_results(self, tmp_path):
        # Regression: scan() used to store parse_results' tuple as the
        # findings list whenever grype flagged an unknown source.
        sbom = tmp_path / "sbom.spdx.json"
        sbom.write_text("{}")
        report = {"matches": [], "source": {"target": "unknown"}}

        def fake_run(cmd, capture_output, text):
            out = cmd[cmd.index("--file") + 1]
            with open(out, "w") as fh:
                json.dump(report, fh)
            return MagicMock(returncode=0, stderr="")

        with patch("argus.scanners.grype.subprocess.run", side_effect=fake_run):
            result = GrypeScanner().scan(".", {"sbom_path": str(sbom)})
        assert result.findings == []
        assert "source.target=unknown" in result.metadata["warning"]
        assert result.metadata["os_packages_evaluated"] is False
