"""Tests for the GuardDog malicious-package scanner.

Fixtures under tests/fixtures/scanner-outputs/guarddog/ are schema-accurate
(built from GuardDog's actual JSON serialization — `verify` emits a list of
{dependency, version, result{issues, results, errors, path}}). They should be
regenerated from a real `guarddog ... verify --output-format=json` run when the
tool is available in CI.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from argus.core.models import Severity
from argus.scanners import SCANNER_REGISTRY
from argus.scanners.guarddog import GuardDogScanner

FIXTURES = Path(__file__).parent.parent.parent.parent / "tests" / "fixtures" / "scanner-outputs" / "guarddog"


def _load(name: str) -> list:
    return json.loads((FIXTURES / name).read_text())


# --------------------------------------------------------------------- #
# registration + capabilities                                          #
# --------------------------------------------------------------------- #


def test_registered():
    assert SCANNER_REGISTRY.get("guarddog") is GuardDogScanner


def test_capabilities():
    assert GuardDogScanner.category == "supply-chain"
    assert GuardDogScanner.supports_vex is False
    assert GuardDogScanner.supports_sbom is False


def test_install_command():
    assert "pip install guarddog" in (GuardDogScanner().install_command() or "")


def test_container_args_contract_returns_list():
    # Satisfies the scanner container-args contract (orchestrator-style, [] —
    # GuardDog runs per-manifest locally, no single containerized invocation).
    assert GuardDogScanner().container_args({}) == []
    assert GuardDogScanner().container_args(None) == []


# --------------------------------------------------------------------- #
# parse_verify                                                          #
# --------------------------------------------------------------------- #


def test_parse_extracts_one_finding_per_triggered_rule():
    data = _load("verify-with-findings.json")
    findings = GuardDogScanner().parse_verify(data, "pypi", Path("requirements.txt"))
    # evil-typosquat triggers exec-base64 + code-execution; requests triggers none.
    assert len(findings) == 2
    rules = {f.metadata["rule"] for f in findings}
    assert rules == {"exec-base64", "code-execution"}
    for f in findings:
        assert f.severity is Severity.HIGH
        assert f.metadata["package"] == "evil-typosquat"
        assert f.metadata["ecosystem"] == "pypi"
        assert f.id.startswith("GUARDDOG-")


def test_matched_code_snippet_never_leaks_into_findings():
    """GuardDog match ``code`` excerpts must not reach argus-results.json."""
    data = _load("verify-with-findings.json")
    findings = GuardDogScanner().parse_verify(data, "pypi", Path("requirements.txt"))
    blob = json.dumps([f.to_dict() for f in findings])
    # The fixture's malicious snippets and the base64 payload must be absent.
    assert "cGF5bG9hZC1zZWNyZXQtZG9fbm90X2xlYWs" not in blob
    assert "exfil.example" not in blob
    assert "os.system" not in blob


def test_zero_findings():
    data = _load("verify-zero-findings.json")
    assert GuardDogScanner().parse_verify(data, "pypi", Path("requirements.txt")) == []


def test_parse_tolerates_malformed():
    assert GuardDogScanner().parse_verify({}, "pypi", Path("x")) == []
    assert GuardDogScanner().parse_verify(["not-a-dict"], "pypi", Path("x")) == []


# --------------------------------------------------------------------- #
# manifest discovery + scan()                                          #
# --------------------------------------------------------------------- #


def test_find_manifests_maps_ecosystems_and_skips_vendored(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "go.mod").write_text("module x\n")
    nm = tmp_path / "node_modules" / "dep"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text("{}")  # must be skipped (vendored)

    found = GuardDogScanner()._find_manifests(tmp_path)
    names = {p.name for p in found}
    assert names == {"requirements.txt", "go.mod"}


def test_scan_reports_note_when_no_manifests(tmp_path):
    result = GuardDogScanner().scan(str(tmp_path))
    assert result.findings == []
    assert "no supported dependency manifests" in result.metadata.get("note", "")


def test_scan_runs_verify_and_collects(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("evil-typosquat==6.6.6\n")
    scanner = GuardDogScanner()
    monkeypatch.setattr(
        scanner, "_run_verify",
        lambda eco, manifest, cfg: _load("verify-with-findings.json"),
    )
    result = scanner.scan(str(tmp_path))
    assert len(result.findings) == 2
    assert any("pypi:" in s for s in result.metadata["manifests_scanned"])


def test_scan_records_tool_error_without_dropping(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("x\n")
    scanner = GuardDogScanner()

    def boom(eco, manifest, cfg):
        raise RuntimeError("guarddog exploded")

    monkeypatch.setattr(scanner, "_run_verify", boom)
    result = scanner.scan(str(tmp_path))
    assert result.findings == []
    assert "errors" in result.metadata


# --------------------------------------------------------------------- #
# _run_verify (subprocess wiring)                                       #
# --------------------------------------------------------------------- #


def _completed(stdout="", stderr="", rc=0):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


def test_run_verify_builds_command_with_rule_flags(tmp_path, monkeypatch):
    captured = {}

    def fake_run(cmd, *a, **k):
        captured["cmd"] = list(cmd)
        return _completed(stdout="[]")

    monkeypatch.setattr("subprocess.run", fake_run)
    data = GuardDogScanner()._run_verify(
        "pypi", Path("requirements.txt"),
        {"rules": ["exec-base64"], "exclude_rules": ["noise-rule"]},
    )
    cmd = captured["cmd"]
    assert cmd[:4] == ["guarddog", "pypi", "verify", "requirements.txt"]
    assert "--output-format=json" in cmd
    assert "--rules" in cmd and "exec-base64" in cmd
    assert "--exclude-rules" in cmd and "noise-rule" in cmd
    assert data == []


def test_run_verify_parses_json_list(tmp_path, monkeypatch):
    payload = json.dumps([{"dependency": "p", "version": "1", "result": {"issues": 0, "results": {}}}])
    monkeypatch.setattr("subprocess.run", lambda cmd, *a, **k: _completed(stdout=payload))
    data = GuardDogScanner()._run_verify("pypi", Path("requirements.txt"), {})
    assert data[0]["dependency"] == "p"


def test_run_verify_empty_output_raises(monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda cmd, *a, **k: _completed(stdout="", stderr="boom"))
    with pytest.raises(RuntimeError, match="boom"):
        GuardDogScanner()._run_verify("pypi", Path("requirements.txt"), {})


def test_run_verify_bad_json_raises(monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda cmd, *a, **k: _completed(stdout="{not json"))
    with pytest.raises(RuntimeError, match="JSON parse error"):
        GuardDogScanner()._run_verify("pypi", Path("requirements.txt"), {})


def test_run_verify_missing_binary_raises(monkeypatch):
    def boom(cmd, *a, **k):
        raise FileNotFoundError

    monkeypatch.setattr("subprocess.run", boom)
    with pytest.raises(RuntimeError, match="not found"):
        GuardDogScanner()._run_verify("pypi", Path("requirements.txt"), {})


def test_run_verify_timeout_raises(monkeypatch):
    def slow(cmd, *a, **k):
        raise subprocess.TimeoutExpired(cmd, 600)

    monkeypatch.setattr("subprocess.run", slow)
    with pytest.raises(RuntimeError, match="timed out"):
        GuardDogScanner()._run_verify("pypi", Path("requirements.txt"), {})
