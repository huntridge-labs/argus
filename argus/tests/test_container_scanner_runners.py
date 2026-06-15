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
    _CONTAINER_DOCKER_CONFIG,
    RegistryAuthError,
    _docker_env_flags,
    _docker_login_mount_args,
    _is_path_component_prefix,
    _normalize_image_ref,
    _redact_cmd_for_log,
    _registry_auth_env,
    _resolve_registry_auth,
    _run_grype,
    _run_syft,
    _run_trivy,
    _subprocess_env,
    _validate_scanner_output,
    validate_registry_auth,
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

    def test_remote_target_is_prefixed_with_registry_scheme(
        self, tmp_path, monkeypatch,
    ):
        """For registry scans (``local=False``), the ref MUST be
        prefixed with ``registry:`` — Grype's default source order
        is ``docker → podman → snap``, and from inside the grype
        container none of those are available. Without the explicit
        prefix Grype never reaches the registry source where the
        ``GRYPE_REGISTRY_AUTH_*`` env vars take effect, so private
        registries silently get anonymous pulls.

        Regression guard for #180: this assertion used to verify the
        opposite (bare ref, no prefix), which baked the silent-auth-
        failure into the test suite.
        """
        self._force_local_binary(monkeypatch)
        captured = {}

        def fake_run(cmd, **_kwargs):
            captured["cmd"] = list(cmd)
            (tmp_path / "grype-results.json").write_text('{"matches": []}')
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)
        _run_grype("registry.example/myapp:1.0", tmp_path, local=False)

        assert "registry:registry.example/myapp:1.0" in captured["cmd"]
        # The bare un-prefixed ref must NOT be on the cmd — it would
        # be ambiguous and Grype would try docker-daemon first.
        assert "registry.example/myapp:1.0" not in captured["cmd"]


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

        def fake_trivy(image_ref, tmp_path, local=False, **_kwargs):
            if "trivy" in write_files:
                (tmp_path / "trivy-results.json").write_text('{"Results": []}')
            return []

        def fake_grype(image_ref, tmp_path, local=False, **_kwargs):
            if "grype" in write_files:
                (tmp_path / "grype-results.json").write_text('{"matches": []}')
            return []

        def fake_syft(image_ref, tmp_path, **_kwargs):
            if "syft" in write_files:
                (tmp_path / "syft-sbom.json").write_text('{"artifacts": []}')

        monkeypatch.setattr(scanner_mod, "_run_trivy", fake_trivy)
        monkeypatch.setattr(scanner_mod, "_run_grype", fake_grype)
        monkeypatch.setattr(scanner_mod, "_run_syft", fake_syft)
        # These tests pass ref-only targets, which would otherwise make
        # scan_image shell out to a real ``docker image inspect`` (#233
        # daemon probe). Pin it so the suite stays hermetic and fast —
        # the local/remote flag is irrelevant to the persistence layer
        # under test here.
        monkeypatch.setattr(scanner_mod, "is_image_local", lambda ref: False)

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

        def fake_trivy(image_ref, tmp_path, local=False, **_kwargs):
            (tmp_path / "trivy-results.json").touch()  # 0-byte
            return []

        monkeypatch.setattr(scanner_mod, "_run_trivy", fake_trivy)
        monkeypatch.setattr(scanner_mod, "_run_grype", lambda *a, **kw: [])
        monkeypatch.setattr(scanner_mod, "_run_syft", lambda *a, **kw: None)
        monkeypatch.setattr(scanner_mod, "is_image_local", lambda ref: False)

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
        def fake_trivy(image_ref, tmp_path, local=False, **_kwargs):
            return [Finding(
                id="CVE-2024-9999", severity=Severity.HIGH, title="test",
                cve="CVE-2024-9999", scanner="trivy",
            )]

        # Grype raises the new structured RuntimeError.
        def fake_grype(image_ref, tmp_path, local=False, **_kwargs):
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


# ───────────────────────────────────────────────
# Engine error-path dockerfile propagation
# ───────────────────────────────────────────────


class TestEngineErrorPathsCarryDockerfile:
    """Every engine path that builds a ContainerScanResult must
    carry the originating Dockerfile + context, including the failure
    paths. Otherwise a build error or an OS error would lose the
    dockerfile reference and a security reviewer couldn't trace which
    container the error belongs to.
    """

    def _engine(self):
        from argus.container.engine import ContainerEngine
        return ContainerEngine({})

    def _build_target(self, tmp_path):
        from argus.container.discovery import ContainerTarget
        return ContainerTarget(
            name="myapp",
            image_ref="myapp:argus-scan",
            dockerfile=tmp_path / "Dockerfile",
            context=tmp_path,
        )

    def test_build_failure_preserves_dockerfile(self, tmp_path, monkeypatch):
        target = self._build_target(tmp_path)
        # Pretend build failed.
        monkeypatch.setattr(
            "argus.container.engine.build_image", lambda t: False,
        )
        # Disk-space probe — return enough to avoid the OOD message branch.
        monkeypatch.setattr(
            "argus.container.engine.check_disk_space", lambda: 10 * 1024**3,
        )
        result = self._engine()._process_target(target)
        assert result.build_success is False
        assert result.dockerfile == str(tmp_path / "Dockerfile")
        assert result.context == str(tmp_path)

    def test_oserror_during_scan_preserves_dockerfile(self, tmp_path, monkeypatch):
        target = self._build_target(tmp_path)
        monkeypatch.setattr(
            "argus.container.engine.build_image", lambda t: True,
        )
        monkeypatch.setattr(
            "argus.container.engine.scan_image",
            lambda *a, **kw: (_ for _ in ()).throw(OSError("disk full")),
        )
        result = self._engine()._process_target(target)
        assert "OS error" in result.scan_error
        assert result.dockerfile == str(tmp_path / "Dockerfile")
        assert result.context == str(tmp_path)

    def test_generic_exception_during_scan_preserves_dockerfile(
        self, tmp_path, monkeypatch,
    ):
        target = self._build_target(tmp_path)
        monkeypatch.setattr(
            "argus.container.engine.build_image", lambda t: True,
        )
        monkeypatch.setattr(
            "argus.container.engine.scan_image",
            lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("oops")),
        )
        result = self._engine()._process_target(target)
        assert "Scan failed" in result.scan_error
        assert result.dockerfile == str(tmp_path / "Dockerfile")
        assert result.context == str(tmp_path)


# ───────────────────────────────────────────────
# scan_image happy-path threading
# ───────────────────────────────────────────────


class TestScanImageThreadsDockerfile:
    """The happy-path ContainerScanResult from ``scan_image`` must
    also carry dockerfile/context from the target."""

    def test_scan_image_populates_dockerfile_from_target(
        self, tmp_path, monkeypatch,
    ):
        from argus.container.discovery import ContainerTarget
        from argus.container.scanner import scan_image

        target = ContainerTarget(
            name="myapp",
            image_ref="myapp:argus-scan",
            dockerfile=tmp_path / "Dockerfile.x",
            context=tmp_path,
        )

        # Stub out the actual scanners — we only need scan_image to
        # construct the result and return.
        monkeypatch.setattr(
            "argus.container.scanner._run_trivy",
            lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            "argus.container.scanner._run_grype",
            lambda *a, **kw: [],
        )

        result = scan_image(target, scanners=("trivy", "grype"))
        assert result.dockerfile == str(tmp_path / "Dockerfile.x")
        assert result.context == str(tmp_path)

    def test_scan_image_remote_pull_leaves_dockerfile_empty(
        self, tmp_path, monkeypatch,
    ):
        from argus.container.discovery import ContainerTarget
        from argus.container.scanner import scan_image

        # Remote-pull entry — no dockerfile, no context.
        target = ContainerTarget(name="webapp", image_ref="myorg/webapp:1.0")

        monkeypatch.setattr(
            "argus.container.scanner._run_trivy",
            lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            "argus.container.scanner._run_grype",
            lambda *a, **kw: [],
        )
        # Genuine remote pull — pin the daemon probe (#233) to "absent"
        # so the test asserts the remote-pull shape deterministically
        # regardless of what's cached on the host running the suite.
        monkeypatch.setattr(
            "argus.container.scanner.is_image_local", lambda ref: False,
        )

        result = scan_image(target, scanners=("trivy", "grype"))
        assert result.dockerfile == ""
        assert result.context == ""


# ───────────────────────────────────────────────
# Local-daemon detection for ref-only targets (#233)
# ───────────────────────────────────────────────
#
# CI commonly builds a throwaway image in one step (``app:scan-<sha>``),
# then scans it by ref in a later step via
# ``argus scan container --image app:scan-<sha>``. The target carries no
# Dockerfile, so the old ``is_local = target.dockerfile is not None`` test
# classified it as a *remote* image — grype/trivy fell through to the
# ``registry:`` source and resolved the never-pushed dev tag against
# Docker Hub (``docker.io/library/...``), failing with
# ``UNAUTHORIZED: authentication required``. The fix also probes the local
# Docker daemon, so an image already present there scans via ``docker:``.


class TestScanImageLocalDaemonDetection:
    """``is_local`` must reflect daemon presence, not just Dockerfile origin."""

    def _capture_local_flag(self, monkeypatch):
        """Stub the runners to record the ``local`` flag they receive.

        Returns a dict the assertions read after ``scan_image`` runs.
        """
        from argus.container import scanner as scanner_mod

        captured: dict = {}

        def fake_grype(image_ref, tmp_path, local=False, **_kwargs):
            captured["grype_local"] = local
            return []

        def fake_trivy(image_ref, tmp_path, local=False, **_kwargs):
            captured["trivy_local"] = local
            return []

        monkeypatch.setattr(scanner_mod, "_run_grype", fake_grype)
        monkeypatch.setattr(scanner_mod, "_run_trivy", fake_trivy)
        return captured

    def test_ref_only_target_present_in_daemon_is_local(self, monkeypatch, caplog):
        """No Dockerfile, but the image sits in the local daemon →
        ``local=True`` so grype/trivy use the ``docker:`` source. The
        choice is logged (transparency breadcrumb) since we did not
        build the image ourselves."""
        from argus.container import scanner as scanner_mod
        from argus.container.scanner import scan_image
        from argus.container.discovery import ContainerTarget

        captured = self._capture_local_flag(monkeypatch)
        # Pretend ``docker image inspect`` succeeds for this ref.
        monkeypatch.setattr(scanner_mod, "is_image_local", lambda ref: True)

        target = ContainerTarget(
            name="opa", image_ref="hardening-test-opa:scan-6d7bd4a0",
        )
        with caplog.at_level("INFO", logger="argus.container"):
            scan_image(target, scanners=("trivy", "grype"), sbom=False)

        assert captured["grype_local"] is True
        assert captured["trivy_local"] is True
        # Operators get a breadcrumb that the local copy was scanned
        # (not pulled from a registry) — the ref appears in the log.
        joined = " ".join(r.message for r in caplog.records)
        assert "local Docker daemon" in joined
        assert "hardening-test-opa:scan-6d7bd4a0" in joined

    def test_ref_only_target_absent_from_daemon_is_remote(self, monkeypatch):
        """No Dockerfile and not in the daemon → genuine remote pull,
        ``local=False`` so the ``registry:`` source + auth env apply."""
        from argus.container import scanner as scanner_mod
        from argus.container.scanner import scan_image
        from argus.container.discovery import ContainerTarget

        captured = self._capture_local_flag(monkeypatch)
        monkeypatch.setattr(scanner_mod, "is_image_local", lambda ref: False)

        target = ContainerTarget(name="webapp", image_ref="ghcr.io/org/web:1.0")
        scan_image(target, scanners=("trivy", "grype"), sbom=False)

        assert captured["grype_local"] is False
        assert captured["trivy_local"] is False

    def test_dockerfile_target_skips_daemon_probe(self, tmp_path, monkeypatch, caplog):
        """When we built the image this run, ``local`` is already known —
        the daemon probe is short-circuited (no redundant subprocess) and
        the not-built-by-us breadcrumb does not fire."""
        from argus.container import scanner as scanner_mod
        from argus.container.scanner import scan_image
        from argus.container.discovery import ContainerTarget

        captured = self._capture_local_flag(monkeypatch)

        probed = {"called": False}

        def boom(ref):
            probed["called"] = True
            return False

        monkeypatch.setattr(scanner_mod, "is_image_local", boom)

        target = ContainerTarget(
            name="myapp",
            image_ref="myapp:argus-scan",
            dockerfile=tmp_path / "Dockerfile",
            context=tmp_path,
        )
        with caplog.at_level("INFO", logger="argus.container"):
            scan_image(target, scanners=("trivy", "grype"), sbom=False)

        # Short-circuit: ``dockerfile is not None`` makes ``is_local`` True
        # without ever consulting the daemon.
        assert captured["grype_local"] is True
        assert probed["called"] is False
        # We built it, so the "found in local daemon" breadcrumb (meant
        # for refs we did NOT build) must not appear.
        assert "local Docker daemon" not in " ".join(
            r.message for r in caplog.records
        )


# ───────────────────────────────────────────────
# Registry credential forwarding (#180)
# ───────────────────────────────────────────────
#
# The user-visible bug: ``argus scan container --config argus.yml``
# against a private registry (Iron Bank, GHCR-private, ECR, etc.)
# silently runs the sub-scanners with anonymous pulls because the
# resolved registry credentials were never threaded into either the
# subprocess env (local-binary path) or the ``docker run`` argv
# (container-fallback path). These tests pin the fix from both ends:
# the pure helpers in isolation, plus the runners' final cmd shape
# under each backend.


class TestRegistryAuthEnv:
    """Pure-function checks for ``_registry_auth_env``."""

    def test_returns_empty_when_config_is_none(self):
        assert _registry_auth_env(None) == {}

    def test_returns_empty_when_config_has_no_creds(self):
        assert _registry_auth_env({}) == {}

    def test_resolves_literal_username_and_password(self):
        env = _registry_auth_env({
            "registry_username": "alice",
            "registry_password": "s3cret",
        })
        # Each tool's native env var receives the same resolved value.
        assert env["TRIVY_USERNAME"] == "alice"
        assert env["GRYPE_REGISTRY_AUTH_USERNAME"] == "alice"
        assert env["SYFT_REGISTRY_AUTH_USERNAME"] == "alice"
        assert env["TRIVY_PASSWORD"] == "s3cret"
        assert env["GRYPE_REGISTRY_AUTH_PASSWORD"] == "s3cret"
        assert env["SYFT_REGISTRY_AUTH_PASSWORD"] == "s3cret"

    def test_resolves_env_var_reference(self, monkeypatch):
        # The preferred shape — argus.yml names the env var, the
        # actual secret lives in the runner's environment.
        monkeypatch.setenv("IRONBANK_USER", "c_pesicka")
        monkeypatch.setenv("IRONBANK_CLI_SECRET", "tok-abc-123")
        env = _registry_auth_env({
            "registry_username_env": "IRONBANK_USER",
            "registry_password_env": "IRONBANK_CLI_SECRET",
        })
        assert env["TRIVY_USERNAME"] == "c_pesicka"
        assert env["TRIVY_PASSWORD"] == "tok-abc-123"

    def test_unset_env_var_resolves_to_empty(self, monkeypatch):
        # When the referenced env var isn't set, the secret resolver
        # returns None and we skip that credential entirely — the scan
        # proceeds anonymously rather than crashing. Regression guard:
        # this used to be a silent corruption (half-credentials sent
        # to the registry) before resolve_secret started returning
        # None cleanly.
        monkeypatch.delenv("NOT_SET_ANYWHERE", raising=False)
        env = _registry_auth_env({
            "registry_username_env": "NOT_SET_ANYWHERE",
            "registry_password_env": "NOT_SET_ANYWHERE",
        })
        assert env == {}


class TestDockerEnvFlags:
    """Pure-function check for the ``-e VAR=value`` flag builder."""

    def test_empty_input_yields_empty_list(self):
        assert _docker_env_flags({}) == []

    def test_produces_e_var_value_pairs(self):
        flags = _docker_env_flags({"FOO": "bar", "BAZ": "qux"})
        # The pairing matters — ``-e`` must immediately precede each
        # VAR=value token, otherwise ``docker run`` parses them as
        # positional args.
        assert flags[::2] == ["-e", "-e"]
        assert set(flags[1::2]) == {"FOO=bar", "BAZ=qux"}


class TestSubprocessEnv:
    """``_subprocess_env`` overlays auth vars onto the host env or returns None."""

    def test_returns_none_when_no_auth(self):
        # None lets subprocess.run inherit the host env unchanged —
        # critical for not breaking the no-creds case (every CI run
        # without registry auth depends on this).
        assert _subprocess_env({}) is None

    def test_layers_auth_on_top_of_os_environ(self, monkeypatch):
        monkeypatch.setenv("PATH", "/usr/bin")
        env = _subprocess_env({"TRIVY_USERNAME": "alice"})
        assert env is not None
        assert env["TRIVY_USERNAME"] == "alice"
        assert env["PATH"] == "/usr/bin"  # host env preserved


class TestDockerLoginMountArgs:
    """``_docker_login_mount_args`` bridges host ``docker login`` creds into
    the Docker-fallback scanner container (the private-ECR fix)."""

    def _write_host_config(self, monkeypatch, tmp_path, payload):
        """Point DOCKER_CONFIG at a fresh dir holding the given config.json."""
        host_dir = tmp_path / "hostdocker"
        host_dir.mkdir()
        (host_dir / "config.json").write_text(json.dumps(payload), encoding="utf-8")
        monkeypatch.setenv("DOCKER_CONFIG", str(host_dir))
        return host_dir

    def test_local_scan_never_mounts(self, monkeypatch, tmp_path):
        # Local-image scans read the docker daemon over the socket, not
        # the registry — no credentials to bridge.
        self._write_host_config(
            monkeypatch, tmp_path,
            {"auths": {"123.dkr.ecr.us-east-1.amazonaws.com": {"auth": "QVdTOnRvaw=="}}},
        )
        assert _docker_login_mount_args(tmp_path, local=True) == []

    def test_no_host_config_yields_no_mount(self, monkeypatch, tmp_path):
        # Anonymous public scans (the default) must be completely
        # unaffected — no host login, no mount, no behavior change.
        monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "does-not-exist"))
        assert _docker_login_mount_args(tmp_path, local=False) == []

    def test_inline_auth_is_mounted_and_sanitized(self, monkeypatch, tmp_path):
        # The ECR case: `aws ecr get-login-password | docker login` writes
        # an inline base64 auth. It must reach the scanner, with the
        # unusable credsStore stripped out.
        self._write_host_config(monkeypatch, tmp_path, {
            "auths": {"123.dkr.ecr.us-east-1.amazonaws.com": {"auth": "QVdTOnRvaw=="}},
            "credsStore": "ecr-login",
        })
        args = _docker_login_mount_args(tmp_path, local=False)

        # Mount + DOCKER_CONFIG env pointed at the in-container path.
        assert "-v" in args and "-e" in args
        assert f"DOCKER_CONFIG={_CONTAINER_DOCKER_CONFIG}" in args
        mount = args[args.index("-v") + 1]
        host_side, container_side, mode = mount.rsplit(":", 2)
        assert container_side == _CONTAINER_DOCKER_CONFIG
        assert mode == "ro"

        # Staged config keeps the inline auth and drops the helper directive.
        staged = json.loads(
            (tmp_path / ".docker" / "config.json").read_text(encoding="utf-8")
        )
        assert staged == {
            "auths": {"123.dkr.ecr.us-east-1.amazonaws.com": {"auth": "QVdTOnRvaw=="}}
        }
        assert "credsStore" not in staged

    def test_helper_only_config_yields_no_mount(self, monkeypatch, tmp_path):
        # If every entry is helper-backed (no inline auth), there's nothing
        # the scanner container could use without the absent helper binary.
        self._write_host_config(monkeypatch, tmp_path, {
            "auths": {"123.dkr.ecr.us-east-1.amazonaws.com": {}},
            "credsStore": "ecr-login",
        })
        assert _docker_login_mount_args(tmp_path, local=False) == []

    def test_malformed_config_is_skipped(self, monkeypatch, tmp_path):
        host_dir = tmp_path / "hostdocker"
        host_dir.mkdir()
        (host_dir / "config.json").write_text("{not json", encoding="utf-8")
        monkeypatch.setenv("DOCKER_CONFIG", str(host_dir))
        assert _docker_login_mount_args(tmp_path, local=False) == []


class TestRedactCmdForLog:
    """``_redact_cmd_for_log`` masks credential values but keeps argv shape."""

    def test_redacts_known_credential_values(self):
        cmd = [
            "docker", "run", "--rm",
            "-e", "TRIVY_USERNAME=alice",
            "-e", "TRIVY_PASSWORD=s3cret-token",
            "-v", "/tmp/argus:/output",
            "aquasec/trivy:0.70.0",
            "image", "--format", "json",
        ]
        out = _redact_cmd_for_log(cmd)
        assert "alice" not in out
        assert "s3cret-token" not in out
        assert "***REDACTED***" in out
        # Names must still be visible — debugging requires seeing
        # WHICH vars are forwarded, just not their values.
        assert "TRIVY_USERNAME" in out
        assert "TRIVY_PASSWORD" in out
        # Non-credential args must pass through verbatim.
        assert "/tmp/argus:/output" in out
        assert "aquasec/trivy:0.70.0" in out

    def test_non_credential_env_vars_pass_through(self):
        # If we ever add other -e flags (HTTP_PROXY, etc.) they
        # should NOT be redacted — only the named credential set.
        cmd = ["docker", "run", "-e", "HTTP_PROXY=http://proxy:8080", "img"]
        out = _redact_cmd_for_log(cmd)
        assert "http://proxy:8080" in out

    def test_handles_cmd_with_no_env_flags(self):
        cmd = ["docker", "run", "--rm", "aquasec/trivy", "image", "ref"]
        assert _redact_cmd_for_log(cmd) == "docker run --rm aquasec/trivy image ref"


# ───────────────────────────────────────────────
# Runner integration: cred flags reach the docker-run argv
# ───────────────────────────────────────────────


def _force_container_path(monkeypatch, tool: str):
    """Make ``_run_<tool>`` take the Docker-fallback branch.

    Returns a list that ``fake_run`` callers can append the
    intercepted cmd into for assertion.
    """
    monkeypatch.setattr(
        "argus.container.scanner.shutil.which",
        lambda name: None,
    )
    monkeypatch.setattr(
        "argus.container_runtime.is_available", lambda: True,
    )
    monkeypatch.setattr(
        "argus.container_runtime.pull_image",
        lambda *a, **kw: True,
    )
    monkeypatch.setattr(
        "argus.container_runtime.runtime_cmd", lambda: "docker",
    )
    monkeypatch.setattr(
        "argus.containers.get_image",
        lambda name: f"fake/{name}:test",
    )


class TestRunTrivyForwardsCredsInContainer:
    """The user's #180 acceptance matrix: trivy in container, creds reach argv."""

    def test_scan_cmd_includes_e_flags_for_trivy_creds(self, tmp_path, monkeypatch):
        _force_container_path(monkeypatch, "trivy")

        intercepted: list[list[str]] = []

        def fake_run(cmd, **_kwargs):
            intercepted.append(list(cmd))
            # Write a valid (empty-results) JSON so the parser doesn't
            # blow up after subprocess.run returns.
            (tmp_path / "trivy-results.json").write_text('{"Results": []}')
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)

        config = {
            "registry_username": "alice",
            "registry_password": "s3cret",
        }
        _run_trivy(
            "registry1.example.com/myapp@sha256:" + "a" * 64,
            tmp_path, local=False, config=config,
        )

        # Two subprocess.run calls — DB pre-warm, then scan. The scan
        # is the second one (DB-only step intentionally does NOT
        # carry cred flags since it pulls from public ghcr.io).
        assert len(intercepted) == 2
        scan_cmd = intercepted[1]
        # The pairing of -e and VAR=value tokens must survive.
        e_pairs = {
            (scan_cmd[i + 1])
            for i, t in enumerate(scan_cmd)
            if t == "-e" and i + 1 < len(scan_cmd)
        }
        assert "TRIVY_USERNAME=alice" in e_pairs
        assert "TRIVY_PASSWORD=s3cret" in e_pairs

    def test_no_creds_no_e_flags(self, tmp_path, monkeypatch):
        _force_container_path(monkeypatch, "trivy")
        # Isolate from any host `docker login` so this exercises the genuine
        # "no auth anywhere" case. Point DOCKER_CONFIG at an empty dir (no
        # config.json) so _docker_login_mount_args is inert — otherwise the
        # runner's ambient ~/.docker/config.json would (correctly) inject a
        # docker-config mount + `-e DOCKER_CONFIG`, which is what
        # test_no_config_creds_but_host_login_mounts_config covers.
        monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "empty-docker"))
        intercepted: list[list[str]] = []

        def fake_run(cmd, **_kwargs):
            intercepted.append(list(cmd))
            (tmp_path / "trivy-results.json").write_text('{"Results": []}')
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)

        _run_trivy(
            "library/nginx:latest",
            tmp_path, local=False, config=None,
        )

        # The no-creds path is the original behavior; argv must not
        # acquire stray ``-e`` flags that older docker daemons in
        # constrained CI might reject.
        scan_cmd = intercepted[-1]
        assert "-e" not in scan_cmd

    def test_no_config_creds_but_host_login_mounts_config(self, tmp_path, monkeypatch):
        # The ECR scenario: the user passes no registry_username/registry_auth
        # to Argus and instead authenticates the host with `docker login`.
        # Those credentials must still reach trivy inside the fallback
        # container — via a read-only mount of the (sanitized) host config
        # with DOCKER_CONFIG pointed at it.
        _force_container_path(monkeypatch, "trivy")
        host_docker = tmp_path / "hostdocker"
        host_docker.mkdir()
        (host_docker / "config.json").write_text(
            json.dumps({"auths": {"123.dkr.ecr.us-east-1.amazonaws.com": {"auth": "QVdTOnRvaw=="}}}),
            encoding="utf-8",
        )
        monkeypatch.setenv("DOCKER_CONFIG", str(host_docker))
        intercepted: list[list[str]] = []

        def fake_run(cmd, **_kwargs):
            intercepted.append(list(cmd))
            (tmp_path / "trivy-results.json").write_text('{"Results": []}')
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)

        _run_trivy(
            "123.dkr.ecr.us-east-1.amazonaws.com/app:latest",
            tmp_path, local=False, config=None,
        )

        scan_cmd = intercepted[-1]
        joined = " ".join(scan_cmd)
        assert f"DOCKER_CONFIG={_CONTAINER_DOCKER_CONFIG}" in scan_cmd
        assert f":{_CONTAINER_DOCKER_CONFIG}:ro" in joined

    def test_local_built_image_skips_creds_even_if_configured(self, tmp_path, monkeypatch):
        # A locally-built image doesn't pull from any registry; the
        # creds in argus.yml might be for OTHER targets in the same
        # run. Forwarding them here would be harmless but noisy —
        # confirm we don't.
        _force_container_path(monkeypatch, "trivy")
        intercepted: list[list[str]] = []

        def fake_run(cmd, **_kwargs):
            intercepted.append(list(cmd))
            (tmp_path / "trivy-results.json").write_text('{"Results": []}')
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)

        _run_trivy(
            "myapp:argus-scan",
            tmp_path, local=True,
            config={"registry_username": "alice", "registry_password": "s3cret"},
        )
        scan_cmd = intercepted[-1]
        assert "TRIVY_USERNAME=alice" not in " ".join(scan_cmd)


class TestRunGrypeForwardsCredsInContainer:
    """Same acceptance for Grype's native env var names."""

    def test_scan_cmd_includes_e_flags_for_grype_creds(self, tmp_path, monkeypatch):
        _force_container_path(monkeypatch, "grype")
        intercepted: list[list[str]] = []

        def fake_run(cmd, **_kwargs):
            intercepted.append(list(cmd))
            (tmp_path / "grype-results.json").write_text('{"matches": []}')
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)

        config = {
            "registry_username": "alice",
            "registry_password": "s3cret",
        }
        _run_grype(
            "registry1.example.com/myapp@sha256:" + "a" * 64,
            tmp_path, local=False, config=config,
        )

        assert len(intercepted) == 2  # DB update + scan
        scan_cmd = intercepted[1]
        joined = " ".join(scan_cmd)
        assert "-e GRYPE_REGISTRY_AUTH_USERNAME=alice" in joined
        assert "-e GRYPE_REGISTRY_AUTH_PASSWORD=s3cret" in joined


class TestRunSyftForwardsCredsInContainer:
    """Syft uses its own env-var names."""

    def test_cmd_includes_e_flags_for_syft_creds(self, tmp_path, monkeypatch):
        _force_container_path(monkeypatch, "syft")
        intercepted: list[list[str]] = []

        def fake_run(cmd, **_kwargs):
            intercepted.append(list(cmd))
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)

        config = {
            "registry_username": "alice",
            "registry_password": "s3cret",
        }
        _run_syft(
            "registry1.example.com/myapp@sha256:" + "a" * 64,
            tmp_path, local=False, config=config,
        )

        assert len(intercepted) == 1
        joined = " ".join(intercepted[0])
        assert "-e SYFT_REGISTRY_AUTH_USERNAME=alice" in joined
        assert "-e SYFT_REGISTRY_AUTH_PASSWORD=s3cret" in joined


class TestLocalBinaryPathReceivesCredsViaEnv:
    """Local trivy/grype/syft inherit creds through subprocess env."""

    def test_local_trivy_receives_auth_env(self, tmp_path, monkeypatch):
        # Pretend trivy is on PATH so the container fallback is skipped.
        monkeypatch.setattr(
            "argus.container.scanner.shutil.which",
            lambda name: "/usr/local/bin/trivy" if name == "trivy" else None,
        )
        captured_env: dict = {}

        def fake_run(cmd, **kwargs):
            captured_env.update(kwargs.get("env") or {})
            (tmp_path / "trivy-results.json").write_text('{"Results": []}')
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)

        _run_trivy(
            "registry1.example.com/myapp@sha256:" + "a" * 64,
            tmp_path, local=False,
            config={"registry_username": "alice", "registry_password": "s3cret"},
        )

        # The local-binary path used to call subprocess.run with no env
        # argument, so resolved creds never reached trivy unless the
        # user separately exported them. Fix: layer the auth env onto
        # os.environ. Regression guard.
        assert captured_env.get("TRIVY_USERNAME") == "alice"
        assert captured_env.get("TRIVY_PASSWORD") == "s3cret"


# ───────────────────────────────────────────────
# Multi-registry credential map (registry_auth)
# ───────────────────────────────────────────────
#
# Operators often pull from multiple registries in a single scan run
# (Iron Bank + GHCR + ECR). And within one registry, different repo
# paths can need different credentials (Iron Bank's restricted vs
# open tiers, Artifactory tenants per project). The registry_auth
# map keys credentials by registry-host + optional path prefix and
# resolves them per-image via longest-prefix matching.


class TestNormalizeImageRef:
    """``_normalize_image_ref`` strips tag and digest, preserves host."""

    def test_strips_digest(self):
        assert _normalize_image_ref(
            "registry1.dso.mil/org/repo@sha256:" + "a" * 64,
        ) == "registry1.dso.mil/org/repo"

    def test_strips_tag(self):
        assert _normalize_image_ref(
            "registry1.dso.mil/org/repo:1.2.3",
        ) == "registry1.dso.mil/org/repo"

    def test_strips_tag_then_digest(self):
        assert _normalize_image_ref(
            "registry1.dso.mil/org/repo:1.2.3@sha256:" + "b" * 64,
        ) == "registry1.dso.mil/org/repo"

    def test_preserves_host_port(self):
        # The colon in ``localhost:5000`` is host:port, not tag.
        # Stripping naively would lose the port.
        assert _normalize_image_ref(
            "localhost:5000/org/repo:1.2.3",
        ) == "localhost:5000/org/repo"


class TestPathComponentPrefix:
    """``_is_path_component_prefix`` rejects string-prefix false matches."""

    def test_exact_match(self):
        assert _is_path_component_prefix(
            "registry1.dso.mil", "registry1.dso.mil",
        ) is True

    def test_proper_prefix_with_boundary(self):
        assert _is_path_component_prefix(
            "registry1.dso.mil/ironbank/restricted",
            "registry1.dso.mil/ironbank/restricted/repo",
        ) is True

    def test_string_prefix_without_boundary_rejected(self):
        # The whole point of the helper: ``restricted`` must NOT match
        # ``restrictedX``. A user-config typo creating that false match
        # used to be a silent privilege-broadening bug.
        assert _is_path_component_prefix(
            "registry1.dso.mil/ironbank/restricted",
            "registry1.dso.mil/ironbank/restrictedX/repo",
        ) is False

    def test_empty_prefix_never_matches(self):
        # An empty string is technically a prefix of everything; we
        # treat it as "no match" so missing/blank keys don't shadow
        # real entries.
        assert _is_path_component_prefix("", "anything") is False


class TestResolveRegistryAuthLongestPrefix:
    """``_resolve_registry_auth`` picks the most specific entry."""

    def test_picks_specific_over_broad(self, monkeypatch):
        monkeypatch.setenv("IB_DEFAULT_USER", "default-user")
        monkeypatch.setenv("IB_DEFAULT_SECRET", "default-secret")
        monkeypatch.setenv("IB_RESTRICTED_USER", "restricted-user")
        monkeypatch.setenv("IB_RESTRICTED_SECRET", "restricted-secret")

        config = {
            "registry_auth": {
                "registry1.dso.mil": {
                    "username_env": "IB_DEFAULT_USER",
                    "password_env": "IB_DEFAULT_SECRET",
                },
                "registry1.dso.mil/ironbank/restricted": {
                    "username_env": "IB_RESTRICTED_USER",
                    "password_env": "IB_RESTRICTED_SECRET",
                },
            },
        }
        username, password = _resolve_registry_auth(
            config,
            "registry1.dso.mil/ironbank/restricted/some-repo/image:1.2.3",
        )
        assert username == "restricted-user"
        assert password == "restricted-secret"

    def test_falls_back_to_broader_entry_when_path_differs(self, monkeypatch):
        # An image under the *open* path uses the bare-host entry,
        # not the restricted-path one.
        monkeypatch.setenv("IB_DEFAULT_USER", "default-user")
        monkeypatch.setenv("IB_DEFAULT_SECRET", "default-secret")
        monkeypatch.setenv("IB_RESTRICTED_USER", "restricted-user")
        monkeypatch.setenv("IB_RESTRICTED_SECRET", "restricted-secret")

        config = {
            "registry_auth": {
                "registry1.dso.mil": {
                    "username_env": "IB_DEFAULT_USER",
                    "password_env": "IB_DEFAULT_SECRET",
                },
                "registry1.dso.mil/ironbank/restricted": {
                    "username_env": "IB_RESTRICTED_USER",
                    "password_env": "IB_RESTRICTED_SECRET",
                },
            },
        }
        username, password = _resolve_registry_auth(
            config,
            "registry1.dso.mil/ironbank/opensource/bigbang/podinfo@sha256:" + "a" * 64,
        )
        assert username == "default-user"
        assert password == "default-secret"

    def test_path_boundary_prevents_false_match(self, monkeypatch):
        # ``restricted`` key must NOT match a sibling repo named
        # ``restrictedX`` — that user-config typo would otherwise
        # silently broaden auth to repos the user didn't intend.
        monkeypatch.setenv("RESTRICTED_USER", "restricted-user")
        monkeypatch.setenv("RESTRICTED_SECRET", "restricted-secret")
        config = {
            "registry_auth": {
                "registry1.dso.mil/ironbank/restricted": {
                    "username_env": "RESTRICTED_USER",
                    "password_env": "RESTRICTED_SECRET",
                },
            },
        }
        username, password = _resolve_registry_auth(
            config,
            "registry1.dso.mil/ironbank/restrictedX/repo:1.0",
        )
        # No match → falls through to the bare-default (which is also
        # unset here) → both None.
        assert username is None
        assert password is None

    def test_falls_back_to_top_level_when_no_map_entry_matches(self, monkeypatch):
        monkeypatch.setenv("FALLBACK_USER", "fallback-user")
        monkeypatch.setenv("FALLBACK_SECRET", "fallback-secret")
        config = {
            "registry_username_env": "FALLBACK_USER",
            "registry_password_env": "FALLBACK_SECRET",
            "registry_auth": {
                "ghcr.io/myorg": {
                    "username_env": "GHCR_USER",
                    "password_env": "GHCR_TOKEN",
                },
            },
        }
        username, password = _resolve_registry_auth(
            config, "docker.io/library/nginx:latest",
        )
        # docker.io image doesn't match any map entry → bare default.
        assert username == "fallback-user"
        assert password == "fallback-secret"

    def test_no_fallback_when_map_match_has_unresolved_env(
        self, monkeypatch, caplog,
    ):
        # The privilege-broadening guard from the design doc.
        # User set a restricted entry but forgot to export
        # IB_RESTRICTED_SECRET. We MUST NOT silently use the bare-
        # default creds for that restricted repo — same rule as
        # k8s imagePullSecrets.
        monkeypatch.setenv("FALLBACK_USER", "fallback-user")
        monkeypatch.setenv("FALLBACK_SECRET", "fallback-secret")
        monkeypatch.delenv("IB_RESTRICTED_USER", raising=False)
        monkeypatch.delenv("IB_RESTRICTED_SECRET", raising=False)
        config = {
            "registry_username_env": "FALLBACK_USER",
            "registry_password_env": "FALLBACK_SECRET",
            "registry_auth": {
                "registry1.dso.mil/ironbank/restricted": {
                    "username_env": "IB_RESTRICTED_USER",
                    "password_env": "IB_RESTRICTED_SECRET",
                },
            },
        }
        with caplog.at_level("WARNING"):
            username, password = _resolve_registry_auth(
                config,
                "registry1.dso.mil/ironbank/restricted/repo:1.0",
            )
        # The matched-but-unresolved case → no creds, NOT the fallback.
        assert username is None
        assert password is None
        # And the user gets a diagnostic naming the unset env var.
        joined = " ".join(r.message for r in caplog.records)
        assert "IB_RESTRICTED" in joined

    def test_non_mapping_entry_is_skipped_with_warning(self, monkeypatch, caplog):
        # Defensive: a malformed YAML where someone wrote
        # ``registry1.dso.mil: token`` instead of the mapping form
        # should warn, not crash.
        config = {
            "registry_auth": {
                "registry1.dso.mil": "not-a-mapping",
            },
        }
        with caplog.at_level("WARNING"):
            username, password = _resolve_registry_auth(
                config, "registry1.dso.mil/foo/bar:1.0",
            )
        assert username is None
        assert password is None
        joined = " ".join(r.message for r in caplog.records)
        assert "not a mapping" in joined


class TestRegistryAuthEnvWithImageRef:
    """``_registry_auth_env`` integrates the map-aware resolver."""

    def test_uses_per_registry_creds_when_image_ref_supplied(self, monkeypatch):
        monkeypatch.setenv("IB_USER", "ib-user")
        monkeypatch.setenv("IB_TOKEN", "ib-token")
        monkeypatch.setenv("GHCR_USER", "gh-user")
        monkeypatch.setenv("GHCR_TOKEN", "gh-token")
        config = {
            "registry_auth": {
                "registry1.dso.mil": {
                    "username_env": "IB_USER",
                    "password_env": "IB_TOKEN",
                },
                "ghcr.io": {
                    "username_env": "GHCR_USER",
                    "password_env": "GHCR_TOKEN",
                },
            },
        }
        env_ib = _registry_auth_env(
            config,
            "registry1.dso.mil/foo/bar@sha256:" + "a" * 64,
        )
        assert env_ib["TRIVY_USERNAME"] == "ib-user"
        assert env_ib["GRYPE_REGISTRY_AUTH_PASSWORD"] == "ib-token"

        env_gh = _registry_auth_env(config, "ghcr.io/myorg/app:1.0")
        assert env_gh["TRIVY_USERNAME"] == "gh-user"
        assert env_gh["GRYPE_REGISTRY_AUTH_PASSWORD"] == "gh-token"

    def test_skips_map_when_image_ref_is_none(self, monkeypatch):
        # Back-compat: helper-level unit tests that exercise the
        # single-default shape without manufacturing an image ref.
        config = {
            "registry_username": "alice",
            "registry_password": "s3cret",
            "registry_auth": {
                # This entry must be ignored when image_ref is None.
                "registry1.dso.mil": {
                    "username": "ironbank-user",
                    "password": "ironbank-token",
                },
            },
        }
        env = _registry_auth_env(config, image_ref=None)
        assert env["TRIVY_USERNAME"] == "alice"
        assert "ironbank-user" not in env.values()


# ───────────────────────────────────────────────
# execution.registry / registry_map plumbing (#186)
# ───────────────────────────────────────────────
#
# The source-scan path routes scanner-image pulls through
# ArgusEngine._resolve_image, which reads execution.registry /
# registry_map from ArgusConfig. The container-scan path consumes a
# dict (not ArgusConfig) and used to pull raw upstream refs regardless
# of the operator's mirror policy. Fix: _load_container_config stashes
# the execution.* values under synthetic underscore keys, and the
# runners call _resolve_sub_scanner_image at every get_image() →
# pull_image() site.


class TestResolveSubScannerImage:
    """Helper-level checks for the container-side resolver wrapper."""

    def test_returns_unchanged_when_no_config(self):
        from argus.container.scanner import _resolve_sub_scanner_image
        assert _resolve_sub_scanner_image(
            "aquasec/trivy:0.70.0", None,
        ) == "aquasec/trivy:0.70.0"
        assert _resolve_sub_scanner_image("aquasec/trivy:0.70.0", {}) == "aquasec/trivy:0.70.0"

    def test_returns_unchanged_when_no_synthetic_keys_set(self):
        # A config with creds / scanners / images but no
        # _execution_registry* must NOT rewrite — back-compat guard
        # for every operator that hasn't set up a mirror.
        from argus.container.scanner import _resolve_sub_scanner_image
        assert _resolve_sub_scanner_image(
            "aquasec/trivy:0.70.0",
            {"registry_username_env": "FOO", "images": []},
        ) == "aquasec/trivy:0.70.0"

    def test_applies_registry_map(self):
        from argus.container.scanner import _resolve_sub_scanner_image
        rewritten = _resolve_sub_scanner_image(
            "aquasec/trivy:0.70.0",
            {"_execution_registry_map": {"docker.io": "harbor.corp/dockerhub-cache"}},
        )
        assert rewritten == "harbor.corp/dockerhub-cache/aquasec/trivy:0.70.0"

    def test_falls_back_to_flat_registry(self):
        from argus.container.scanner import _resolve_sub_scanner_image
        rewritten = _resolve_sub_scanner_image(
            "ghcr.io/google/osv-scanner:v2.3.6",
            {
                "_execution_registry_map": {"docker.io": "harbor.corp/dockerhub-cache"},
                "_execution_registry": "harbor.corp/argus",
            },
        )
        # ghcr.io has no map entry → flat ``_execution_registry`` wins.
        assert rewritten == "harbor.corp/argus/google/osv-scanner:v2.3.6"


class TestRunTrivyUsesResolvedImage:
    """The ``docker run`` cmd argv carries the mirror-rewritten image."""

    def test_trivy_docker_run_uses_mapped_mirror(self, tmp_path, monkeypatch):
        _force_container_path(monkeypatch, "trivy")
        intercepted: list[list[str]] = []

        def fake_run(cmd, **_kwargs):
            intercepted.append(list(cmd))
            (tmp_path / "trivy-results.json").write_text('{"Results": []}')
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)

        # ``_force_container_path`` mocks get_image to return
        # ``fake/trivy:test`` — a bare-name docker.io shape. The map
        # routes docker.io to harbor.corp/dockerhub-cache, so the cmd
        # should reference the mirror path.
        _run_trivy(
            "registry.example.com/myapp@sha256:" + "a" * 64,
            tmp_path, local=False,
            config={
                "_execution_registry_map": {
                    "docker.io": "harbor.corp/dockerhub-cache",
                },
            },
        )

        # DB pre-warm + scan = 2 invocations. BOTH must use the
        # rewritten image — pulling the DB from upstream when the
        # operator has a mirror configured would defeat the mirror.
        assert len(intercepted) == 2
        for cmd in intercepted:
            joined = " ".join(cmd)
            assert "harbor.corp/dockerhub-cache/fake/trivy:test" in joined
            # The bare upstream form must NOT appear as the image
            # positional — that's the pre-fix bug shape.
            assert "fake/trivy:test " not in joined.replace(
                "harbor.corp/dockerhub-cache/fake/trivy:test", "",
            )

    def test_trivy_unchanged_when_no_mirror_config(self, tmp_path, monkeypatch):
        # Critical back-compat: configs without any execution.* synthetic
        # key see the original ``fake/trivy:test`` ref unchanged.
        _force_container_path(monkeypatch, "trivy")
        intercepted: list[list[str]] = []

        def fake_run(cmd, **_kwargs):
            intercepted.append(list(cmd))
            (tmp_path / "trivy-results.json").write_text('{"Results": []}')
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)
        _run_trivy(
            "library/nginx:latest",
            tmp_path, local=False, config=None,
        )

        for cmd in intercepted:
            joined = " ".join(cmd)
            assert "fake/trivy:test" in joined
            assert "harbor" not in joined  # no rewrite occurred


class TestRunGrypeUsesResolvedImage:
    """Grype's docker-run cmd honors the mirror config the same way Trivy does."""

    def test_grype_docker_run_uses_mapped_mirror(self, tmp_path, monkeypatch):
        _force_container_path(monkeypatch, "grype")
        intercepted: list[list[str]] = []

        def fake_run(cmd, **_kwargs):
            intercepted.append(list(cmd))
            (tmp_path / "grype-results.json").write_text('{"matches": []}')
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)
        _run_grype(
            "registry.example.com/myapp@sha256:" + "a" * 64,
            tmp_path, local=False,
            config={
                "_execution_registry_map": {
                    "docker.io": "harbor.corp/dockerhub-cache",
                },
            },
        )

        # DB update + scan = 2 invocations. Both use rewritten image.
        assert len(intercepted) == 2
        for cmd in intercepted:
            assert "harbor.corp/dockerhub-cache/fake/grype:test" in " ".join(cmd)


class TestRunSyftUsesResolvedImage:
    """Syft's docker-run cmd honors the mirror config."""

    def test_syft_docker_run_uses_mapped_mirror(self, tmp_path, monkeypatch):
        _force_container_path(monkeypatch, "syft")
        intercepted: list[list[str]] = []

        def fake_run(cmd, **_kwargs):
            intercepted.append(list(cmd))
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)
        _run_syft(
            "registry.example.com/myapp@sha256:" + "a" * 64,
            tmp_path, local=False,
            config={
                "_execution_registry_map": {
                    "docker.io": "harbor.corp/dockerhub-cache",
                },
            },
        )

        assert len(intercepted) == 1
        assert "harbor.corp/dockerhub-cache/fake/syft:test" in " ".join(intercepted[0])


class TestScanImageBindsContentDigest:
    """scan_image records the scanned image's content digest (#237) so a
    clean scan attests *what* was scanned, not just a mutable tag."""

    def test_digest_populated_and_stamped_on_findings(self, monkeypatch):
        from argus.container import scanner as scanner_mod
        from argus.container.scanner import scan_image
        from argus.container.discovery import ContainerTarget
        from argus.core.models import Finding, Severity

        finding = Finding(
            id="CVE-2024-1", severity=Severity.HIGH, title="vuln",
            scanner="container", cve="CVE-2024-1",
            metadata={"package": "openssl"},
        )
        monkeypatch.setattr(scanner_mod, "_run_trivy", lambda *a, **kw: [finding])
        monkeypatch.setattr(scanner_mod, "_run_grype", lambda *a, **kw: [])
        monkeypatch.setattr(scanner_mod, "is_image_local", lambda ref: True)
        monkeypatch.setattr(scanner_mod, "get_image_digest", lambda ref: "sha256:deadbeef")

        target = ContainerTarget(name="app", image_ref="app:scan-6d7bd4a0")
        result = scan_image(target, scanners=("trivy",), sbom=False)

        # Result-level digest → per-image markdown + audit manifest.
        assert result.digest == "sha256:deadbeef"
        # Finding-level metadata → argus-results.json / SARIF.
        f = result.combined_findings[0]
        assert f.metadata["image_digest"] == "sha256:deadbeef"
        assert f.metadata["image_ref"] == "app:scan-6d7bd4a0"
        assert f.metadata["package"] == "openssl"  # existing metadata preserved

    def test_unknown_digest_is_non_fatal(self, monkeypatch):
        """docker absent / inspect failed → empty digest, no metadata stamp,
        scan still succeeds (mirrors is_image_local's degrade-to-safe)."""
        from argus.container import scanner as scanner_mod
        from argus.container.scanner import scan_image
        from argus.container.discovery import ContainerTarget
        from argus.core.models import Finding, Severity

        finding = Finding(
            id="CVE-2024-2", severity=Severity.LOW, title="v",
            scanner="container", metadata={},
        )
        monkeypatch.setattr(scanner_mod, "_run_trivy", lambda *a, **kw: [finding])
        monkeypatch.setattr(scanner_mod, "_run_grype", lambda *a, **kw: [])
        monkeypatch.setattr(scanner_mod, "is_image_local", lambda ref: False)
        monkeypatch.setattr(scanner_mod, "get_image_digest", lambda ref: "")

        target = ContainerTarget(name="app", image_ref="ghcr.io/org/app:1.0")
        result = scan_image(target, scanners=("trivy",), sbom=False)

        assert result.digest == ""
        assert "image_digest" not in result.combined_findings[0].metadata


# ───────────────────────────────────────────────
# Registry auth fast-fail (#253)
# ───────────────────────────────────────────────
#
# Before this gate a registry_auth entry whose ``*_env`` named an unset
# variable only produced a WARNING in argus.log; the scan proceeded and
# the sub-scanner container failed ~90s later with an opaque
# ``UNAUTHORIZED: authentication required``. ``validate_registry_auth``
# now fails fast — on stderr, before any container starts — naming the
# registry scope and the unset variable.


class TestValidateRegistryAuth:
    """Pure-function checks for ``validate_registry_auth``."""

    def test_raises_on_map_entry_unresolved_password_env(self, monkeypatch):
        # Mirrors the issue example exactly: username resolves, password
        # env var is unset → fail fast naming the registry + the var.
        monkeypatch.setenv("ARGUS_REGISTRY_USER", "svc-account")
        monkeypatch.delenv("ARGUS_REGISTRY_PASSWORD", raising=False)
        config = {
            "registry_auth": {
                "containers.va.ghe.com": {
                    "username_env": "ARGUS_REGISTRY_USER",
                    "password_env": "ARGUS_REGISTRY_PASSWORD",
                },
            },
        }
        with pytest.raises(RegistryAuthError) as excinfo:
            validate_registry_auth(
                config, "containers.va.ghe.com/org/repo:1.0",
            )
        msg = str(excinfo.value)
        assert "registry_auth[containers.va.ghe.com]" in msg
        assert "password unresolved" in msg
        assert "ARGUS_REGISTRY_PASSWORD" in msg
        # Second line is the actionable remediation.
        assert "argus.yml" in msg

    def test_raises_on_map_entry_unresolved_username_env(self, monkeypatch):
        monkeypatch.delenv("IB_USER", raising=False)
        monkeypatch.setenv("IB_TOKEN", "tok")
        config = {
            "registry_auth": {
                "registry1.dso.mil": {
                    "username_env": "IB_USER",
                    "password_env": "IB_TOKEN",
                },
            },
        }
        with pytest.raises(RegistryAuthError) as excinfo:
            validate_registry_auth(config, "registry1.dso.mil/org/repo:1.0")
        msg = str(excinfo.value)
        assert "username unresolved" in msg
        assert "IB_USER" in msg

    def test_raises_on_empty_env_var(self, monkeypatch):
        # Set-but-empty counts as unresolved (the upstream pull would
        # still fail). ``not username`` covers "" the same as None.
        monkeypatch.setenv("IB_USER", "")
        config = {
            "registry_auth": {
                "registry1.dso.mil": {"username_env": "IB_USER"},
            },
        }
        with pytest.raises(RegistryAuthError):
            validate_registry_auth(config, "registry1.dso.mil/org/repo:1.0")

    def test_raises_on_top_level_unresolved(self, monkeypatch):
        # No map match → top-level single-default shortcut is gated too.
        monkeypatch.delenv("REG_PASS", raising=False)
        config = {"registry_password_env": "REG_PASS"}
        with pytest.raises(RegistryAuthError) as excinfo:
            validate_registry_auth(config, "ghcr.io/org/app:1.0")
        assert "REG_PASS" in str(excinfo.value)

    def test_top_level_gated_when_image_ref_none(self, monkeypatch):
        # Helper-level callers may pass image_ref=None; the top-level
        # shortcut still needs gating.
        monkeypatch.delenv("REG_PASS", raising=False)
        config = {"registry_password_env": "REG_PASS"}
        with pytest.raises(RegistryAuthError):
            validate_registry_auth(config, None)

    def test_no_raise_when_creds_resolve(self, monkeypatch):
        monkeypatch.setenv("IB_USER", "u")
        monkeypatch.setenv("IB_TOKEN", "p")
        config = {
            "registry_auth": {
                "registry1.dso.mil": {
                    "username_env": "IB_USER",
                    "password_env": "IB_TOKEN",
                },
            },
        }
        # No exception.
        validate_registry_auth(config, "registry1.dso.mil/org/repo:1.0")

    def test_no_raise_for_anonymous_pull(self):
        # Nothing configured → anonymous is a valid mode, not an error.
        validate_registry_auth({}, "docker.io/library/nginx:latest")
        validate_registry_auth(None, "docker.io/library/nginx:latest")

    def test_no_raise_when_unconfigured_field_omitted(self, monkeypatch):
        # Token-only auth: only password is configured (and resolves);
        # the absent username must NOT be gated.
        monkeypatch.setenv("IB_TOKEN", "p")
        monkeypatch.delenv("IB_USER", raising=False)
        config = {
            "registry_auth": {
                "registry1.dso.mil": {"password_env": "IB_TOKEN"},
            },
        }
        validate_registry_auth(config, "registry1.dso.mil/org/repo:1.0")

    def test_no_raise_when_no_entry_matches_image(self, monkeypatch):
        # A configured-but-unresolved entry for a *different* registry
        # must not gate a pull from an unrelated registry.
        monkeypatch.delenv("IB_TOKEN", raising=False)
        config = {
            "registry_auth": {
                "registry1.dso.mil": {"password_env": "IB_TOKEN"},
            },
        }
        validate_registry_auth(config, "ghcr.io/org/app:1.0")

    def test_malformed_entry_is_not_gated(self, monkeypatch):
        # Non-mapping entry is a config-shape problem handled (warned)
        # elsewhere — not an unresolved-credential failure.
        config = {"registry_auth": {"registry1.dso.mil": "not-a-mapping"}}
        validate_registry_auth(config, "registry1.dso.mil/org/repo:1.0")

    def test_longest_prefix_entry_is_the_one_gated(self, monkeypatch):
        # The more-specific entry wins; its unresolved cred is what
        # fails, even though the broader entry resolves fine.
        monkeypatch.setenv("BROAD_USER", "u")
        monkeypatch.setenv("BROAD_PASS", "p")
        monkeypatch.delenv("RESTRICTED_PASS", raising=False)
        config = {
            "registry_auth": {
                "registry1.dso.mil": {
                    "username_env": "BROAD_USER",
                    "password_env": "BROAD_PASS",
                },
                "registry1.dso.mil/ironbank/restricted": {
                    "username_env": "BROAD_USER",
                    "password_env": "RESTRICTED_PASS",
                },
            },
        }
        with pytest.raises(RegistryAuthError) as excinfo:
            validate_registry_auth(
                config, "registry1.dso.mil/ironbank/restricted/repo:1.0",
            )
        assert "ironbank/restricted" in str(excinfo.value)
        assert "RESTRICTED_PASS" in str(excinfo.value)


class TestScanImageFailsFastOnRegistryAuth:
    """``scan_image`` gates remote pulls before any sub-scanner runs."""

    def _stub_runners(self, monkeypatch):
        """Record whether the sub-scanner runners are ever reached."""
        from argus.container import scanner as scanner_mod

        called: dict = {"trivy": False, "grype": False}

        def fake_trivy(*_a, **_kw):
            called["trivy"] = True
            return []

        def fake_grype(*_a, **_kw):
            called["grype"] = True
            return []

        monkeypatch.setattr(scanner_mod, "_run_trivy", fake_trivy)
        monkeypatch.setattr(scanner_mod, "_run_grype", fake_grype)
        return called

    def test_remote_unresolved_raises_before_subscanners(
        self, monkeypatch,
    ):
        from argus.container import scanner as scanner_mod
        from argus.container.scanner import scan_image
        from argus.container.discovery import ContainerTarget

        called = self._stub_runners(monkeypatch)
        monkeypatch.setattr(scanner_mod, "is_image_local", lambda ref: False)
        monkeypatch.delenv("ARGUS_REGISTRY_PASSWORD", raising=False)

        config = {
            "registry_auth": {
                "ghcr.io": {"password_env": "ARGUS_REGISTRY_PASSWORD"},
            },
        }
        target = ContainerTarget(name="web", image_ref="ghcr.io/org/web:1.0")

        with pytest.raises(RegistryAuthError):
            scan_image(target, scanners=("trivy", "grype"), sbom=False, config=config)

        # The whole point: we never spent 60–90s in a doomed pull.
        assert called["trivy"] is False
        assert called["grype"] is False

    def test_local_image_skips_registry_auth_gate(self, monkeypatch):
        # Image present in the daemon → scanned from docker source, no
        # registry pull, so a missing registry cred must NOT block it.
        from argus.container import scanner as scanner_mod
        from argus.container.scanner import scan_image
        from argus.container.discovery import ContainerTarget

        called = self._stub_runners(monkeypatch)
        monkeypatch.setattr(scanner_mod, "is_image_local", lambda ref: True)
        monkeypatch.delenv("ARGUS_REGISTRY_PASSWORD", raising=False)

        config = {
            "registry_auth": {
                "ghcr.io": {"password_env": "ARGUS_REGISTRY_PASSWORD"},
            },
        }
        target = ContainerTarget(name="web", image_ref="ghcr.io/org/web:1.0")

        # No raise; sub-scanners run against the local copy.
        scan_image(target, scanners=("trivy", "grype"), sbom=False, config=config)
        assert called["trivy"] is True
        assert called["grype"] is True


class TestEngineDoesNotSwallowRegistryAuthError:
    """``_process_target`` re-raises the fast-fail instead of recording it."""

    def _engine(self):
        from argus.container.engine import ContainerEngine
        return ContainerEngine({})

    def _remote_target(self):
        from argus.container.discovery import ContainerTarget
        return ContainerTarget(name="web", image_ref="ghcr.io/org/web:1.0")

    def test_registry_auth_error_propagates(self, monkeypatch):
        monkeypatch.setattr(
            "argus.container.engine.scan_image",
            lambda *a, **kw: (_ for _ in ()).throw(
                RegistryAuthError("registry_auth[ghcr.io]: password unresolved"),
            ),
        )
        with pytest.raises(RegistryAuthError):
            self._engine()._process_target(self._remote_target())

    def test_generic_error_still_recorded(self, monkeypatch):
        # Contrast: ordinary scan failures are still caught and turned
        # into a per-target scan_error (existing behavior preserved).
        monkeypatch.setattr(
            "argus.container.engine.scan_image",
            lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        result = self._engine()._process_target(self._remote_target())
        assert "Scan failed" in result.scan_error
