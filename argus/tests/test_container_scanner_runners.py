"""Tests for argus.container.scanner runners — _run_grype, _run_trivy.

Focuses on the failure-mode contract: every sub-scanner runner must
raise a single ``RuntimeError`` shape so the orchestrator can record
the error under ``scanner_errors`` and continue. JSON parse errors,
non-zero exit codes, missing output files, and 0-byte output files
all need to behave the same way — no traceback spam in normal CLI
output, no silent downgrade of scanner coverage.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from argus.container.scanner import (
    _run_grype,
    _run_trivy,
    _validate_scanner_output,
)


def _completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    """Build a stand-in subprocess.CompletedProcess for mock returns."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


# ───────────────────────────────────────────────
# Helper: _validate_scanner_output
# ───────────────────────────────────────────────


class TestValidateScannerOutput:
    """Shared validator used by both Trivy and Grype runners.

    Exercising it directly means the per-runner tests below can focus
    on the parse path; the failure-mode contract is locked in here
    once.
    """

    def test_returns_none_when_all_checks_pass(self, tmp_path):
        out = tmp_path / "results.json"
        out.write_text('{"matches": []}')
        result = _completed(returncode=0)
        # Healthy run — silent return.
        assert _validate_scanner_output("trivy", out, result) is None

    def test_raises_on_nonzero_exit(self, tmp_path):
        out = tmp_path / "results.json"
        out.write_text('{"matches": []}')
        result = _completed(returncode=1, stderr="image not found in registry")
        with pytest.raises(RuntimeError) as excinfo:
            _validate_scanner_output("grype", out, result)
        msg = str(excinfo.value)
        # Exit code + stderr both surface in the message so the user
        # sees the actual reason without bumping log level.
        assert "exit 1" in msg
        assert "image not found" in msg
        assert "grype" in msg

    def test_raises_when_output_file_missing(self, tmp_path):
        # File never created by the scanner — common when the
        # subprocess crashes before reaching the JSON-write step.
        out = tmp_path / "results.json"
        result = _completed(returncode=0)
        with pytest.raises(RuntimeError) as excinfo:
            _validate_scanner_output("grype", out, result)
        assert "no output file" in str(excinfo.value)

    def test_raises_when_output_file_is_zero_bytes(self, tmp_path):
        # The user-reported bug: grype's wrapper exits 0 (or non-zero,
        # depending on the failure mode) but the redirect target file
        # is empty. ``output_file.exists()`` is True but
        # ``json.loads("")`` would crash. The validator catches it.
        out = tmp_path / "results.json"
        out.touch()
        assert out.stat().st_size == 0
        result = _completed(returncode=0)
        with pytest.raises(RuntimeError) as excinfo:
            _validate_scanner_output("grype", out, result)
        assert "empty output file" in str(excinfo.value)

    def test_raises_on_zero_bytes_with_stderr_breadcrumb(self, tmp_path):
        # When the scanner prints to stderr AND writes a 0-byte file,
        # the message has to surface the stderr — that's the actual
        # diagnostic the user needs.
        out = tmp_path / "results.json"
        out.touch()
        result = _completed(returncode=2, stderr="catalog resolution failed: 401")
        with pytest.raises(RuntimeError) as excinfo:
            _validate_scanner_output("grype", out, result)
        assert "catalog resolution failed" in str(excinfo.value)

    def test_clipped_stderr_does_not_truncate_short_messages(self, tmp_path):
        out = tmp_path / "results.json"
        result = _completed(returncode=1, stderr="short reason")
        with pytest.raises(RuntimeError) as excinfo:
            _validate_scanner_output("trivy", out, result)
        # Short stderr is preserved verbatim, no truncation marker.
        assert "short reason" in str(excinfo.value)


# ───────────────────────────────────────────────
# Per-runner regression tests (the user's acceptance matrix)
# ───────────────────────────────────────────────


class TestRunGrype:
    """The four scenarios from the user's bug report acceptance matrix."""

    def _force_local_binary(self, monkeypatch):
        # Pretend ``grype`` is installed locally so we exercise the
        # binary-path branch (no docker fallback) — keeps the test
        # focused on the validation/parse code.
        monkeypatch.setattr(
            "argus.container.scanner.shutil.which",
            lambda name: "/usr/local/bin/grype" if name == "grype" else None,
        )

    def test_nonzero_exit_with_empty_file_raises_runtimeerror(
        self, tmp_path, monkeypatch,
    ):
        """Acceptance: non-zero exit + empty file → no JSONDecodeError
        traceback; structured RuntimeError carrying exit + stderr."""
        self._force_local_binary(monkeypatch)
        # Simulate the grype wrapper writing a 0-byte file then bailing.
        def fake_run(cmd, **_kwargs):
            (tmp_path / "grype-results.json").touch()
            return _completed(
                returncode=1,
                stderr="catalog resolution failed: ENETUNREACH",
            )
        monkeypatch.setattr("subprocess.run", fake_run)

        with pytest.raises(RuntimeError) as excinfo:
            _run_grype("docker:argus-scan", tmp_path, local=True)
        msg = str(excinfo.value)
        assert "exit 1" in msg
        assert "catalog resolution failed" in msg
        # Critically, NOT a json.JSONDecodeError.
        assert "Expecting value" not in msg

    def test_zero_exit_with_empty_file_raises_runtimeerror(
        self, tmp_path, monkeypatch,
    ):
        """Acceptance: zero exit + empty file → still treated as failure
        (the wrapper or scanner crashed but the exit code didn't reflect
        it). Defensive — empty JSON is never a valid grype result."""
        self._force_local_binary(monkeypatch)
        def fake_run(cmd, **_kwargs):
            (tmp_path / "grype-results.json").touch()
            return _completed(returncode=0)
        monkeypatch.setattr("subprocess.run", fake_run)

        with pytest.raises(RuntimeError) as excinfo:
            _run_grype("docker:argus-scan", tmp_path, local=True)
        assert "empty output file" in str(excinfo.value)

    def test_malformed_json_raises_runtimeerror_not_jsondecodeerror(
        self, tmp_path, monkeypatch,
    ):
        """Acceptance: malformed JSON → translated to RuntimeError so the
        engine catches it under ``scanner_errors`` instead of bubbling a
        bare JSONDecodeError to the user."""
        self._force_local_binary(monkeypatch)
        def fake_run(cmd, **_kwargs):
            (tmp_path / "grype-results.json").write_text("{not-valid-json")
            return _completed(returncode=0)
        monkeypatch.setattr("subprocess.run", fake_run)

        with pytest.raises(RuntimeError) as excinfo:
            _run_grype("docker:argus-scan", tmp_path, local=True)
        assert "JSON parse error" in str(excinfo.value)
        # Per the contract: RuntimeError, not the underlying decoder
        # exception type — even though __cause__ chains the original.
        assert not isinstance(excinfo.value, json.JSONDecodeError)

    def test_valid_json_passes_through_to_parser(self, tmp_path, monkeypatch):
        """Acceptance: valid JSON → normal parse path returns findings.
        Confirms the new validation gating doesn't break the happy path."""
        self._force_local_binary(monkeypatch)
        valid_grype_payload = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-1234",
                        "severity": "High",
                        "description": "test",
                        "fix": {"versions": ["1.2.3"], "state": "fixed"},
                    },
                    "artifact": {
                        "name": "openssl",
                        "version": "1.1.1",
                        "purl": "pkg:deb/openssl@1.1.1",
                    },
                },
            ],
        }
        def fake_run(cmd, **_kwargs):
            (tmp_path / "grype-results.json").write_text(
                json.dumps(valid_grype_payload),
            )
            return _completed(returncode=0)
        monkeypatch.setattr("subprocess.run", fake_run)

        findings = _run_grype("docker:argus-scan", tmp_path, local=True)
        assert len(findings) == 1
        assert findings[0].cve == "CVE-2024-1234"


class TestRunTrivy:
    """Mirror coverage for trivy — same failure-mode contract via the
    shared validator. Confirms grype isn't the only beneficiary of the
    parse-path hardening."""

    def _force_local_binary(self, monkeypatch):
        monkeypatch.setattr(
            "argus.container.scanner.shutil.which",
            lambda name: "/usr/local/bin/trivy" if name == "trivy" else None,
        )

    def test_zero_exit_with_empty_file_raises_runtimeerror(
        self, tmp_path, monkeypatch,
    ):
        self._force_local_binary(monkeypatch)
        def fake_run(cmd, **_kwargs):
            (tmp_path / "trivy-results.json").touch()
            return _completed(returncode=0)
        monkeypatch.setattr("subprocess.run", fake_run)

        with pytest.raises(RuntimeError) as excinfo:
            _run_trivy("docker:argus-scan", tmp_path, local=True)
        assert "empty output file" in str(excinfo.value)

    def test_malformed_json_raises_runtimeerror_not_jsondecodeerror(
        self, tmp_path, monkeypatch,
    ):
        self._force_local_binary(monkeypatch)
        def fake_run(cmd, **_kwargs):
            (tmp_path / "trivy-results.json").write_text("{not-valid")
            return _completed(returncode=0)
        monkeypatch.setattr("subprocess.run", fake_run)

        with pytest.raises(RuntimeError) as excinfo:
            _run_trivy("docker:argus-scan", tmp_path, local=True)
        assert "JSON parse error" in str(excinfo.value)


# ───────────────────────────────────────────────
# End-to-end orchestration: error is recorded, not silenced
# ───────────────────────────────────────────────


class TestOrchestratorRecordsScannerError:
    """Closing the loop: when ``_run_grype`` raises RuntimeError, the
    orchestrator must catch it and record under ``scanner_errors`` so
    the summary reflects reality (Grype failed, not "Grype found 0
    matches"). Trivy results in the same scan must still propagate."""

    def test_grype_failure_does_not_silently_drop_other_scanner_findings(
        self, tmp_path, monkeypatch,
    ):
        from argus.container.scanner import scan_image
        from argus.container.discovery import ContainerTarget
        from argus.core.models import Finding, Severity

        target = ContainerTarget(name="app", image_ref="docker:argus-scan")

        # Trivy succeeds with one finding.
        def fake_trivy(image_ref, tmp_path, local=False):
            return [Finding(
                id="CVE-2024-9999", severity=Severity.HIGH, title="test",
                cve="CVE-2024-9999", scanner="trivy",
            )]

        # Grype raises the new structured RuntimeError.
        def fake_grype(image_ref, tmp_path, local=False):
            raise RuntimeError(
                "grype scan failed (exit 1): catalog resolution failed"
            )

        monkeypatch.setattr("argus.container.scanner._run_trivy", fake_trivy)
        monkeypatch.setattr("argus.container.scanner._run_grype", fake_grype)

        result = scan_image(
            target, scanners=["trivy", "grype"], sbom=False,
        )

        # Trivy's contribution is preserved.
        assert len(result.trivy_findings) == 1
        # Grype's failure is recorded structurally — the engine /
        # reporters can surface it instead of pretending grype ran
        # cleanly with zero findings.
        assert "grype" in result.scanner_errors
        assert "catalog resolution failed" in result.scanner_errors["grype"]
        # Combined view doesn't claim grype's missing data is "no
        # vulnerabilities" — it's simply trivy's findings.
        assert len(result.combined_findings) == 1
