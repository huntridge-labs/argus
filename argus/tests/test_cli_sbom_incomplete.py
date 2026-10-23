"""CLI handling of incomplete SBOM-mode results (#492).

An incomplete result (a matcher skipped the SBOM's OS packages) must
never exit 0, with or without ``--fail-on-scanner-error``.
"""

from __future__ import annotations

import argparse
import json
import logging
from unittest.mock import MagicMock

import pytest

from argus.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_SUCCESS, _merge_sbom_summaries, cmd_scan
from argus.core.config import ArgusConfig, ExecutionConfig, ReportingConfig
from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.core.sbom import SbomInfo

_INCOMPLETE_META = {
    "incomplete": True,
    "incomplete_reason": "trivy did not evaluate the SBOM's 3 OS package(s)",
}


def _summary(*results, threshold=None):
    return ScanSummary(results=list(results), severity_threshold=threshold)


def _run_scan(tmp_path, monkeypatch, summaries, threshold=None, fail_on_scanner_error=False):
    """Run ``cmd_scan --sbom <dir>`` with engine.run returning ``summaries``."""
    sboms = tmp_path / "sboms"
    sboms.mkdir()
    for index in range(len(summaries)):
        (sboms / f"s{index}.cdx.json").write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.5", "components": [],
        }))
    cfg = ArgusConfig(
        reporting=ReportingConfig(
            output_dir=str(tmp_path / "out"), formats=[], severity_threshold=threshold,
        ),
        execution=ExecutionConfig(),
    )
    queue = list(summaries)
    monkeypatch.setattr("argus.core.config.ArgusConfig.load", lambda _p: cfg)
    monkeypatch.setattr("argus.core.engine.ArgusEngine.run", lambda self, **kw: queue.pop(0))
    monkeypatch.setattr("argus.core.engine.ArgusEngine.register_scanner", lambda self, _s: None)
    monkeypatch.setattr(
        "argus.core.engine.ArgusEngine.__init__",
        lambda self, _cfg: (
            setattr(self, "config", cfg) or setattr(self, "_scanners", {"trivy": object})
        ),
    )
    monkeypatch.setattr("argus.scanners.get_available_scanners", lambda: [])
    monkeypatch.setattr("argus.reporters.get_reporter", lambda fmt: MagicMock())
    monkeypatch.setattr("argus.audit.get_logger", lambda *a, **kw: logging.getLogger("test"))
    monkeypatch.setattr(
        "argus.audit.create_manifest", lambda **kw: MagicMock(execution_backend=None),
    )
    monkeypatch.setattr("argus.audit.finalize_manifest", lambda *a, **kw: None)
    (tmp_path / "argus.yml").write_text('version: "1.0"\n')
    args = argparse.Namespace(
        command="scan", scanner=None, path=".", config=str(tmp_path / "argus.yml"),
        formats=None, severity_threshold=None, output_dir=str(tmp_path / "out"),
        list=False, verbose=False, exclude="", no_default_excludes=False,
        dry_run=False, fail_fast=False, timeout=None, no_parallel=False,
        allow_local_versions=False, no_cache=False, no_timestamp=True,
        no_spinner=True, output_vars=None, discover=None, images=None,
        scanners=None, target=None, port=None, env_vars=None,
        scan_type="baseline", startup_timeout=60, check_tools=False,
        sbom=str(sboms), fail_on_scanner_error=fail_on_scanner_error,
    )
    return cmd_scan(args)


class TestIncompleteExitCode:
    def test_incomplete_scan_exits_error_by_default(self, tmp_path, monkeypatch):
        rc = _run_scan(tmp_path, monkeypatch, [
            _summary(ScanResult(scanner="trivy", metadata=dict(_INCOMPLETE_META))),
        ])
        assert rc == EXIT_ERROR

    @pytest.mark.parametrize("flag", [True, False])
    def test_flag_does_not_change_the_outcome(self, tmp_path, monkeypatch, flag):
        rc = _run_scan(tmp_path, monkeypatch, [
            _summary(ScanResult(scanner="trivy", metadata=dict(_INCOMPLETE_META))),
        ], fail_on_scanner_error=flag)
        assert rc == EXIT_ERROR

    def test_findings_over_threshold_still_exit_findings(self, tmp_path, monkeypatch):
        finding = Finding(id="CVE-1", severity=Severity.CRITICAL, title="x")
        rc = _run_scan(tmp_path, monkeypatch, [
            _summary(
                ScanResult(scanner="trivy", findings=[finding], metadata=dict(_INCOMPLETE_META)),
                threshold=Severity.HIGH,
            ),
        ], threshold=Severity.HIGH)
        assert rc == EXIT_FINDINGS

    def test_complete_scan_still_succeeds(self, tmp_path, monkeypatch):
        rc = _run_scan(tmp_path, monkeypatch, [_summary(ScanResult(scanner="grype"))])
        assert rc == EXIT_SUCCESS

    def test_incomplete_second_sbom_is_not_lost_in_the_merge(self, tmp_path, monkeypatch):
        rc = _run_scan(tmp_path, monkeypatch, [
            _summary(ScanResult(scanner="trivy")),
            _summary(ScanResult(scanner="trivy", metadata=dict(_INCOMPLETE_META))),
        ])
        assert rc == EXIT_ERROR


class TestMergeKeepsIncomplete:
    def test_any_incomplete_sbom_marks_the_merged_result(self, tmp_path):
        infos = []
        for name in ("a.json", "b.json"):
            path = tmp_path / name
            path.write_text("{}")
            infos.append(SbomInfo(path=path, format="cyclonedx-json"))
        merged = _merge_sbom_summaries(
            [
                (infos[0], _summary(ScanResult(scanner="trivy", metadata={"execution": "local"}))),
                (infos[1], _summary(ScanResult(scanner="trivy", metadata=dict(_INCOMPLETE_META)))),
            ],
            severity_threshold=None,
        )
        result = merged.results[0]
        assert result.incomplete is True
        assert str(infos[1].path) in result.metadata["incomplete_reason"]
        assert merged.passed is False
