"""Tests for argus.scanners.govulncheck — GovulncheckScanner.

govulncheck is the reachability-aware Go scanner: its whole value is
distinguishing vulnerabilities whose affected symbol is *actually called*
from ones merely *present* in the dependency graph. These tests pin that
behavior (the reachability tier), the JSON-stream parsing (govulncheck
emits concatenated objects, not one document), and the standard scanner
metadata/build_args contract.
"""

from __future__ import annotations

import json

import pytest

from argus.core.models import Severity
from argus.core.scanner_template import ScanPaths
from argus.scanners.govulncheck import GovulncheckScanner


class TestGovulncheckParseResults:
    """parse_results over the streamed-JSON fixture."""

    def test_parse_results_with_findings(self, fixtures_dir):
        scanner = GovulncheckScanner()
        path = fixtures_dir / "govulncheck" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        # One finding per vulnerability id (per-level findings collapsed).
        assert len(findings) == 3
        by_id = {f.id: f for f in findings}
        assert set(by_id) == {"GO-2024-0001", "GO-2024-0002", "GO-2023-0003"}

    def test_parse_results_zero_findings(self, fixtures_dir):
        # config + progress messages only, no osv/finding → empty list,
        # NOT a parse error (the stream is well-formed, just vuln-free).
        scanner = GovulncheckScanner()
        path = fixtures_dir / "govulncheck" / "results-zero-findings.json"
        findings = scanner.parse_results(path)
        assert findings == []

    def test_reachable_finding_keeps_real_severity(self, fixtures_dir):
        scanner = GovulncheckScanner()
        path = fixtures_dir / "govulncheck" / "results-with-findings.json"
        by_id = {f.id: f for f in scanner.parse_results(path)}

        called = by_id["GO-2024-0001"]
        assert called.metadata["reachable"] is True
        assert called.severity == Severity.HIGH  # from database_specific.severity
        assert called.cve == "CVE-2024-1111"
        assert called.metadata["fixed_version"] == "v0.23.0"
        assert called.metadata["package"] == "golang.org/x/net/http2"
        # The vulnerable symbol and a reconstructed call stack are captured.
        assert called.metadata["vulnerable_symbol"] == "Server.ServeConn"
        assert called.metadata["call_stack"], "reachable finding should have a call stack"
        # Stack reads entry-point → vulnerable symbol.
        assert "main" in called.metadata["call_stack"][0]
        assert "ServeConn" in called.metadata["call_stack"][-1]

    def test_reachable_finding_without_db_severity_is_unknown(self, fixtures_dir):
        # Go advisories frequently lack a machine-readable severity; the
        # scanner must surface UNKNOWN rather than guessing.
        scanner = GovulncheckScanner()
        path = fixtures_dir / "govulncheck" / "results-with-findings.json"
        by_id = {f.id: f for f in scanner.parse_results(path)}

        called = by_id["GO-2024-0002"]
        assert called.metadata["reachable"] is True
        assert called.severity == Severity.UNKNOWN

    def test_imported_not_called_is_info_and_flagged(self, fixtures_dir):
        # The whole point: a present-but-unreachable vuln must NOT gate.
        scanner = GovulncheckScanner()
        path = fixtures_dir / "govulncheck" / "results-with-findings.json"
        by_id = {f.id: f for f in scanner.parse_results(path)}

        dormant = by_id["GO-2023-0003"]
        assert dormant.metadata["reachable"] is False
        assert dormant.severity == Severity.INFO
        assert "[imported, not called]" in dormant.title
        # No call stack for an unreachable finding.
        assert dormant.metadata["call_stack"] == []

    def test_finding_fields(self, fixtures_dir):
        scanner = GovulncheckScanner()
        path = fixtures_dir / "govulncheck" / "results-with-findings.json"
        by_id = {f.id: f for f in scanner.parse_results(path)}

        f = by_id["GO-2024-0001"]
        assert f.scanner == "govulncheck"
        assert f.metadata["tool"] == "govulncheck"
        assert f.location == "golang.org/x/net/http2@v0.21.0"
        assert f.metadata["details_url"] == "https://pkg.go.dev/vuln/GO-2024-0001"
        assert "CVE-2024-1111" in f.metadata["aliases"]

    def test_malformed_stream_raises_for_engine_to_catch(self, tmp_path):
        # A truncated / non-JSON stream must raise (template surfaces it as
        # parse_failed) rather than silently returning [] — otherwise a
        # broken run reads as "clean, 0 vulns".
        bad = tmp_path / "govulncheck.json"
        bad.write_text('{"config": {"scanner_name": "govulncheck"}} {not json')
        with pytest.raises(json.JSONDecodeError):
            GovulncheckScanner().parse_results(bad)

    def test_empty_output_returns_empty_list(self, tmp_path):
        empty = tmp_path / "govulncheck.json"
        empty.write_text("")
        assert GovulncheckScanner().parse_results(empty) == []


class TestGovulncheckScannerMeta:
    """Scanner metadata + build_args contract."""

    def test_name(self):
        assert GovulncheckScanner().name == "govulncheck"

    def test_category_is_sca(self):
        assert GovulncheckScanner().category == "sca"

    def test_languages(self):
        assert GovulncheckScanner().languages == ["go"]

    def test_install_command(self):
        cmd = GovulncheckScanner().install_command()
        assert cmd is not None
        assert "govulncheck" in cmd

    def test_is_available_true_when_on_path(self, monkeypatch):
        import argus.scanners.govulncheck as mod
        monkeypatch.setattr(
            mod.shutil, "which",
            lambda name: "/usr/local/bin/govulncheck" if name == "govulncheck" else None,
        )
        assert GovulncheckScanner().is_available() is True

    def test_is_available_false_when_absent(self, monkeypatch):
        import argus.scanners.govulncheck as mod
        monkeypatch.setattr(mod.shutil, "which", lambda name: None)
        assert GovulncheckScanner().is_available() is False

    def test_tool_version_none_when_unavailable(self, monkeypatch):
        import argus.scanners.govulncheck as mod
        monkeypatch.setattr(mod.shutil, "which", lambda name: None)
        assert GovulncheckScanner().tool_version() is None

    def test_tool_version_parses_scanner_line(self, monkeypatch):
        import argus.scanners.govulncheck as mod
        monkeypatch.setattr(
            mod.shutil, "which", lambda name: "/usr/local/bin/govulncheck",
        )
        # govulncheck -version prints several lines; the version lives on
        # the "Scanner: govulncheck@vX.Y.Z" line.
        monkeypatch.setattr(
            mod, "parse_tool_version",
            lambda cmd, pattern: "1.1.4",
        )
        assert GovulncheckScanner().tool_version() == "1.1.4"

    def test_registered_in_registry(self):
        from argus.scanners import get_scanner

        scanner = get_scanner("govulncheck")
        assert isinstance(scanner, GovulncheckScanner)

    def test_build_args_default_scans_whole_module(self):
        scanner = GovulncheckScanner()
        paths = ScanPaths(workspace="/workspace", output="/output/results.json")
        args = scanner.build_args(paths, {})
        assert args == ["govulncheck", "-json", "./..."]

    def test_build_args_respects_scan_target(self):
        scanner = GovulncheckScanner()
        paths = ScanPaths(workspace="/workspace", output="/output/results.json")
        args = scanner.build_args(paths, {"scan_target": "./cmd/..."})
        assert args == ["govulncheck", "-json", "./cmd/..."]

    def test_build_args_uses_relative_pattern_not_workspace_path(self):
        # govulncheck resolves ``./...`` against the working directory
        # (cwd=path locally, WORKDIR /workspace in the container). It must
        # NOT receive an absolute mount path — its package loader rejects
        # those. Regression guard against "helpfully" prefixing the
        # workspace like the path-argument scanners (bandit/gosec) do.
        scanner = GovulncheckScanner()
        paths = ScanPaths(workspace="/workspace", output="/output/results.json")
        args = scanner.build_args(paths, {})
        assert "/workspace" not in args
        assert "/workspace/..." not in args


class TestGovulncheckScanWiring:
    """scan() must run the tool inside the target module (cwd=path)."""

    def test_scan_passes_cwd_to_template(self, monkeypatch, tmp_path):
        import argus.scanners.govulncheck as mod

        captured = {}

        def fake_run(scanner, path, config, *, cwd=None, **kwargs):
            captured["path"] = path
            captured["cwd"] = cwd
            from argus.core.models import ScanResult
            return ScanResult(scanner=scanner.name)

        monkeypatch.setattr(mod, "run_subprocess_scan", fake_run)
        GovulncheckScanner().scan(str(tmp_path), {})

        # cwd must equal the scan path so ``govulncheck ./...`` resolves
        # against the module being scanned, not argus's CWD.
        assert captured["cwd"] == str(tmp_path)
        assert captured["path"] == str(tmp_path)
