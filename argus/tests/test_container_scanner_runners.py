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


class TestRunGrypeLocalDaemonScheme:
    """When Grype scans a locally-built image, its CLI source-scheme
    prefix collides with image refs that happen to start with
    ``docker:`` (etc.). The runner forces the docker-daemon source
    explicitly so user-supplied refs are never misparsed.
    """

    def _force_local_binary(self, monkeypatch):
        monkeypatch.setattr(
            "argus.container.scanner.shutil.which",
            lambda name: "/usr/local/bin/grype" if name == "grype" else None,
        )

    def test_local_target_is_prefixed_with_docker_scheme(
        self, tmp_path, monkeypatch,
    ):
        """The image ref grype sees gets a ``docker:`` scheme prefix
        when ``local=True``, so the daemon source is unambiguous."""
        self._force_local_binary(monkeypatch)
        captured = {}

        def fake_run(cmd, **_kwargs):
            captured["cmd"] = list(cmd)
            (tmp_path / "grype-results.json").write_text(
                '{"matches": []}'
            )
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)
        _run_grype("docker:argus-scan", tmp_path, local=True)

        # The argument grype receives is the user's literal ref,
        # prefixed with the scheme. ``docker:argus-scan`` becomes
        # ``docker:docker:argus-scan`` — first half is the scheme,
        # the rest is the daemon image identifier.
        assert "docker:docker:argus-scan" in captured["cmd"]
        # And the bare un-prefixed ref isn't accidentally also there.
        assert captured["cmd"].count("docker:argus-scan") == 0

    def test_local_target_with_clean_ref_still_gets_prefix(
        self, tmp_path, monkeypatch,
    ):
        """Refs that don't collide still get the prefix — uniform
        behavior is easier to reason about than "sometimes prefix"."""
        self._force_local_binary(monkeypatch)
        captured = {}

        def fake_run(cmd, **_kwargs):
            captured["cmd"] = list(cmd)
            (tmp_path / "grype-results.json").write_text('{"matches": []}')
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)
        _run_grype("myapp:dev", tmp_path, local=True)
        assert "docker:myapp:dev" in captured["cmd"]

    def test_remote_target_is_not_prefixed(self, tmp_path, monkeypatch):
        """For registry scans (``local=False``), the original ref
        passes through untouched — the docker-daemon scheme would
        force grype to look at a daemon that doesn't have the image."""
        self._force_local_binary(monkeypatch)
        captured = {}

        def fake_run(cmd, **_kwargs):
            captured["cmd"] = list(cmd)
            (tmp_path / "grype-results.json").write_text('{"matches": []}')
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)
        _run_grype("registry.example/myapp:1.0", tmp_path, local=False)

        assert "registry.example/myapp:1.0" in captured["cmd"]
        # No accidental scheme prefix on remote scans.
        assert "docker:registry.example/myapp:1.0" not in captured["cmd"]


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


class TestScanImageRawOutputPersistence:
    """``scan_image(raw_output_dir=...)`` copies raw scanner artifacts
    into a caller-supplied directory so ``argus-results/<run>/raw/``
    can preserve trivy/grype/syft per-scanner output for forensics
    after the underlying tempdir is cleaned up."""

    def _stub_runners(self, monkeypatch, write_files=("trivy", "grype")):
        """Replace the live scanner runners with stubs that drop the
        files we'd expect to see on a successful real run. Lets these
        tests focus on the copy/persistence layer without touching
        the actual binaries."""
        from argus.container import scanner as scanner_mod

        def fake_trivy(image_ref, tmp_path, local=False):
            if "trivy" in write_files:
                (tmp_path / "trivy-results.json").write_text('{"Results": []}')
            return []

        def fake_grype(image_ref, tmp_path, local=False):
            if "grype" in write_files:
                (tmp_path / "grype-results.json").write_text('{"matches": []}')
            return []

        def fake_syft(image_ref, tmp_path):
            if "syft" in write_files:
                (tmp_path / "syft-sbom.json").write_text('{"artifacts": []}')

        monkeypatch.setattr(scanner_mod, "_run_trivy", fake_trivy)
        monkeypatch.setattr(scanner_mod, "_run_grype", fake_grype)
        monkeypatch.setattr(scanner_mod, "_run_syft", fake_syft)

    def test_raw_outputs_copied_when_dir_supplied(self, tmp_path, monkeypatch):
        from argus.container.scanner import scan_image
        from argus.container.discovery import ContainerTarget

        self._stub_runners(monkeypatch, write_files=("trivy", "grype", "syft"))

        target = ContainerTarget(name="app", image_ref="myapp:dev")
        raw_dir = tmp_path / "raw" / "app"

        scan_image(target, sbom=True, raw_output_dir=raw_dir)

        # All three artifacts persisted at the expected names.
        assert (raw_dir / "trivy-results.json").exists()
        assert (raw_dir / "grype-results.json").exists()
        assert (raw_dir / "syft-sbom.json").exists()
        # Contents survived intact.
        assert "Results" in (raw_dir / "trivy-results.json").read_text()

    def test_no_copy_when_raw_output_dir_is_none(self, tmp_path, monkeypatch):
        # Default path — historic behavior — leaves no artifacts on
        # disk after the tempdir cleanup.
        from argus.container.scanner import scan_image
        from argus.container.discovery import ContainerTarget

        self._stub_runners(monkeypatch)

        target = ContainerTarget(name="app", image_ref="myapp:dev")
        scan_image(target, sbom=False, raw_output_dir=None)

        # No `raw/` directory was created (the test's tmp_path is
        # otherwise empty).
        assert not (tmp_path / "raw").exists()

    def test_partial_outputs_persisted_when_some_scanners_skipped(
        self, tmp_path, monkeypatch,
    ):
        # Only trivy ran (grype skipped or failed); the raw dir
        # contains just trivy's file. Missing files don't block the
        # copy of the ones that exist.
        from argus.container.scanner import scan_image
        from argus.container.discovery import ContainerTarget

        self._stub_runners(monkeypatch, write_files=("trivy",))

        target = ContainerTarget(name="app", image_ref="myapp:dev")
        raw_dir = tmp_path / "raw" / "app"

        scan_image(
            target, scanners=("trivy",), sbom=False,
            raw_output_dir=raw_dir,
        )

        assert (raw_dir / "trivy-results.json").exists()
        assert not (raw_dir / "grype-results.json").exists()
        assert not (raw_dir / "syft-sbom.json").exists()

    def test_zero_byte_files_are_not_persisted(self, tmp_path, monkeypatch):
        # 0-byte files are an explicit failure signal upstream
        # (``_validate_scanner_output`` rejects them). Don't copy
        # them — the persistence layer should never make a 0-byte
        # file look authoritative on disk.
        from argus.container import scanner as scanner_mod
        from argus.container.scanner import scan_image
        from argus.container.discovery import ContainerTarget

        def fake_trivy(image_ref, tmp_path, local=False):
            (tmp_path / "trivy-results.json").touch()  # 0-byte
            return []

        monkeypatch.setattr(scanner_mod, "_run_trivy", fake_trivy)
        monkeypatch.setattr(scanner_mod, "_run_grype", lambda *a, **kw: [])
        monkeypatch.setattr(scanner_mod, "_run_syft", lambda *a, **kw: None)

        raw_dir = tmp_path / "raw" / "app"
        scan_image(
            ContainerTarget(name="app", image_ref="myapp:dev"),
            scanners=("trivy",), sbom=False, raw_output_dir=raw_dir,
        )
        # Either the dir doesn't exist (nothing copied) or it's empty.
        if raw_dir.exists():
            assert not list(raw_dir.iterdir())


class TestContainerCanonicalScanSummary:
    """The container scan flow now also emits the canonical
    ScanSummary shape (the same one source scans use), so
    ``argus view`` and the JSON reporter can render container
    findings without a separate code path."""

    def test_each_target_becomes_a_scanresult_with_combined_findings(
        self, tmp_path, monkeypatch,
    ):
        # Exercises the cli.py snippet that maps ContainerScanResult
        # → ScanResult(scanner=f"container/{name}", ...). Tests a
        # representative subset of the conversion in isolation.
        from argus.core.models import ScanResult, ScanSummary, Finding, Severity
        from argus.container.scanner import (
            ContainerScanResult, ContainerScanSummary,
        )

        f1 = Finding(id="CVE-2024-1", severity=Severity.HIGH, title="t1",
                     cve="CVE-2024-1", scanner="trivy")
        f2 = Finding(id="CVE-2024-2", severity=Severity.MEDIUM, title="t2",
                     cve="CVE-2024-2", scanner="grype")

        container_summary = ContainerScanSummary(
            results=[
                ContainerScanResult(
                    name="webapp",
                    image_ref="myorg/webapp:1.0",
                    combined_findings=[f1, f2],
                    scanner_errors={},
                ),
            ],
        )

        # Mirror cli.py's mapping logic.
        canonical = ScanSummary(results=[
            ScanResult(
                scanner=f"container/{r.name}",
                findings=list(r.combined_findings),
                metadata={
                    "image_ref": r.image_ref,
                    "build_success": r.build_success,
                },
            )
            for r in container_summary.results
        ])

        # The canonical summary round-trips through the same
        # serialization the source-scan flow uses, so ``argus view``
        # treats container findings identically.
        as_dict = canonical.to_dict()
        assert "results" in as_dict
        assert as_dict["results"][0]["scanner"] == "container/webapp"
        assert len(as_dict["results"][0]["findings"]) == 2
        # Per-image metadata lifts onto the ScanResult.
        assert as_dict["results"][0]["metadata"]["image_ref"] == "myorg/webapp:1.0"


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
