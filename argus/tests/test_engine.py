"""Tests for argus.core.engine — ArgusEngine."""

import os
import subprocess
from pathlib import Path

import pytest

from argus.core.config import ArgusConfig, ScannerConfig
from argus.core.engine import ArgusEngine
from argus.core.models import Finding, ScanResult, Severity, ScanSummary


class MockScanner:
    """A mock scanner that returns canned results."""

    def __init__(self, name, findings=None, available=True, container_image=""):
        self.name = name
        self._findings = findings or []
        self._available = available
        self.scan_called_with = None
        self.container_image = container_image

    def scan(self, path, config=None):
        self.scan_called_with = (path, config)
        return ScanResult(scanner=self.name, findings=self._findings)

    def is_available(self):
        return self._available

    def install_command(self):
        return f"pip install {self.name}"

    def container_args(self, config=None):
        return ["scan", "/workspace"]


class TestArgusEngine:
    """Test ArgusEngine orchestration."""

    def _make_engine(self, scanners_config=None, reporting_config=None):
        data = {}
        if scanners_config:
            data["scanners"] = scanners_config
        if reporting_config:
            data["reporting"] = reporting_config
        config = ArgusConfig.from_dict(data)
        return ArgusEngine(config)

    def test_register_scanner(self):
        engine = self._make_engine()
        scanner = MockScanner("bandit")
        engine.register_scanner(scanner)
        assert "bandit" in engine._scanners

    def test_run_all_enabled_scanners(self):
        engine = self._make_engine(
            scanners_config={
                "bandit": {"enabled": True},
                "gitleaks": {"enabled": True},
            }
        )
        findings_a = [Finding(id="1", severity=Severity.HIGH, title="f1")]
        findings_b = [Finding(id="2", severity=Severity.LOW, title="f2")]

        engine.register_scanner(MockScanner("bandit", findings=findings_a))
        engine.register_scanner(MockScanner("gitleaks", findings=findings_b))

        summary = engine.run()
        assert isinstance(summary, ScanSummary)
        assert len(summary.results) == 2
        assert summary.total_count == 2

    def test_run_specific_scanners(self):
        engine = self._make_engine(
            scanners_config={
                "bandit": {"enabled": True},
                "gitleaks": {"enabled": True},
            }
        )
        findings = [Finding(id="1", severity=Severity.HIGH, title="f1")]
        engine.register_scanner(MockScanner("bandit", findings=findings))
        engine.register_scanner(MockScanner("gitleaks"))

        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1
        assert summary.results[0].scanner == "bandit"

    def test_run_skips_disabled_scanners(self):
        engine = self._make_engine(
            scanners_config={
                "bandit": {"enabled": True},
                "gitleaks": {"enabled": False},
            }
        )
        engine.register_scanner(MockScanner("bandit"))
        engine.register_scanner(MockScanner("gitleaks"))

        summary = engine.run()
        assert len(summary.results) == 1
        assert summary.results[0].scanner == "bandit"

    def test_run_surfaces_unavailable_scanner_as_failure_row(self):
        """A scanner the user enabled in config but that isn't installed
        locally surfaces as a failure row, not a silent skip — the user
        explicitly asked for it, so they should see why it didn't run.
        """
        engine = self._make_engine(
            scanners_config={"bandit": {"enabled": True}}
        )
        engine.register_scanner(MockScanner("bandit", available=False))

        summary = engine.run()
        assert len(summary.results) == 1
        assert summary.results[0].metadata.get("execution_failed") is True

    def test_run_skips_unregistered_scanners(self):
        engine = self._make_engine()
        summary = engine.run(scanner_names=["nonexistent"])
        assert len(summary.results) == 0

    def test_run_with_path_override(self):
        engine = self._make_engine(
            scanners_config={"bandit": {"enabled": True, "path": "default"}}
        )
        mock = MockScanner("bandit")
        engine.register_scanner(mock)

        engine.run(path="/override/path")
        assert mock.scan_called_with[0] == "/override/path"

    def test_run_uses_config_path(self):
        engine = self._make_engine(
            scanners_config={"bandit": {"enabled": True, "path": "src"}}
        )
        mock = MockScanner("bandit")
        engine.register_scanner(mock)

        engine.run()
        assert mock.scan_called_with[0] == "src"

    def test_get_available_scanners(self):
        engine = self._make_engine()
        engine.register_scanner(MockScanner("bandit", available=True))
        engine.register_scanner(MockScanner("gitleaks", available=False))
        engine.register_scanner(MockScanner("trivy-iac", available=True))

        available = engine.get_available_scanners()
        assert "bandit" in available
        assert "trivy-iac" in available
        assert "gitleaks" not in available

    def test_run_records_duration_ms_in_metadata(self):
        engine = self._make_engine(
            scanners_config={"bandit": {"enabled": True}}
        )
        findings = [Finding(id="1", severity=Severity.HIGH, title="f1")]
        engine.register_scanner(MockScanner("bandit", findings=findings))

        summary = engine.run(parallel=False)
        assert len(summary.results) == 1
        assert "duration_ms" in summary.results[0].metadata
        assert isinstance(summary.results[0].metadata["duration_ms"], int)
        assert summary.results[0].metadata["duration_ms"] >= 0

    def test_run_handles_scanner_exception(self):
        engine = self._make_engine(
            scanners_config={"bad": {"enabled": True}}
        )

        class FailingScanner:
            name = "bad"

            def scan(self, path, config=None):
                raise RuntimeError("Scanner exploded")

            def is_available(self):
                return True

            def install_command(self):
                return None

        engine.register_scanner(FailingScanner())
        summary = engine.run()
        # Failure row surfaces in canonical results (ADR-016) — silent
        # drops were the bug behind ``lint-dockerfile`` going missing.
        assert len(summary.results) == 1
        assert summary.results[0].metadata.get("execution_failed") is True
        assert summary.results[0].total_count == 0


class TestDockerExecutionBackend:
    """Test Docker execution fallback logic."""

    def _make_engine(self, backend="auto", registry=""):
        data = {
            "execution": {
                "backend": backend,
                "registry": registry,
            },
        }
        return ArgusEngine(ArgusConfig.from_dict(data))

    def test_local_backend_uses_local_scanner(self):
        engine = self._make_engine(backend="local")
        findings = [Finding(id="1", severity=Severity.HIGH, title="f1")]
        scanner = MockScanner("bandit", findings=findings, available=True)
        engine.register_scanner(scanner)

        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1
        assert scanner.scan_called_with is not None

    def test_local_backend_fails_if_unavailable(self):
        engine = self._make_engine(backend="local")
        scanner = MockScanner("bandit", available=False)
        engine.register_scanner(scanner)

        # Engine surfaces the failure as a row with execution_failed
        # metadata (ADR-016 — no silent drops).
        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1
        assert summary.results[0].metadata.get("execution_failed") is True

    def test_auto_backend_defers_to_scan_when_no_build_args(self, monkeypatch):
        """Scanners with a custom ``scan()`` flow but no ``build_args``/
        ``container_args`` (e.g. linters that walk the workspace and
        invoke their tool per file) should defer to ``scanner.scan()``
        instead of the engine's container path.

        Regression for the lint-dockerfile bug: HadolintLinter has
        ``container_image`` set but no ``build_args``, so the engine
        used to AttributeError inside ``_run_in_container`` and the
        scanner silently disappeared from results.
        """
        engine = self._make_engine(backend="auto")
        # Pretend Docker is available so the engine would have chosen
        # the container path if it could.
        monkeypatch.setattr(engine, "_is_docker_available", lambda: True)

        captured: dict = {}

        class CustomScanScanner:
            name = "custom"
            container_image = "example/custom:1.0"
            # Deliberately no build_args or container_args.

            def scan(self, path, config=None):
                captured["scan_called"] = (path, config)
                return ScanResult(
                    scanner=self.name,
                    findings=[Finding(
                        id="X", severity=Severity.LOW, title="from scan()",
                    )],
                )

            def is_available(self):
                return True

            def install_command(self):
                return None

        engine.register_scanner(CustomScanScanner())
        summary = engine.run(scanner_names=["custom"])

        # scan() was called, container path was bypassed, findings flow through.
        assert captured.get("scan_called") is not None
        assert len(summary.results) == 1
        assert len(summary.results[0].findings) == 1
        assert summary.results[0].findings[0].title == "from scan()"

    def test_docker_backend_rejects_scanner_without_build_args(self, monkeypatch):
        """``backend: docker`` must fail loudly when a scanner has a
        container image but no way to run in one — the user explicitly
        opted into container-only execution and silent fallback would
        violate that contract."""
        engine = self._make_engine(backend="docker")
        monkeypatch.setattr(engine, "_is_docker_available", lambda: True)

        class CustomScanScanner:
            name = "custom"
            container_image = "example/custom:1.0"

            def scan(self, path, config=None):
                return ScanResult(scanner=self.name)

            def is_available(self):
                return False

            def install_command(self):
                return None

        engine.register_scanner(CustomScanScanner())
        summary = engine.run(scanner_names=["custom"])
        # Surfaces as a failure row with the loud error.
        assert len(summary.results) == 1
        meta = summary.results[0].metadata
        assert meta.get("execution_failed") is True
        assert "build_args" in meta.get("execution_failure_reason", "")

    def test_resolve_image_no_registry(self):
        engine = self._make_engine(registry="")
        scanner = MockScanner("trivy", container_image="aquasec/trivy:0.58.0")
        assert engine._resolve_image(scanner) == "aquasec/trivy:0.58.0"

    def test_resolve_image_with_registry_override(self):
        engine = self._make_engine(registry="registry.corp/argus")
        scanner = MockScanner("trivy", container_image="aquasec/trivy:0.58.0")
        # Docker Hub shorthand (no dots in first segment) gets registry prefix
        assert engine._resolve_image(scanner) == "registry.corp/argus/aquasec/trivy:0.58.0"

    def test_resolve_image_ghcr_with_registry_override(self):
        engine = self._make_engine(registry="registry.corp/argus")
        scanner = MockScanner("osv", container_image="ghcr.io/google/osv-scanner:1.9.1")
        assert engine._resolve_image(scanner) == "registry.corp/argus/google/osv-scanner:1.9.1"

    def test_resolve_image_empty_returns_empty(self):
        engine = self._make_engine()
        scanner = MockScanner("container", container_image="")
        assert engine._resolve_image(scanner) == ""

    def test_docker_backend_no_image_raises(self):
        engine = self._make_engine(backend="docker")
        scanner = MockScanner("bandit", available=False, container_image="")
        engine.register_scanner(scanner)

        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1
        assert summary.results[0].metadata.get("execution_failed") is True

    def test_auto_backend_prefers_container(self, monkeypatch):
        """auto backend uses containers first when Docker is available."""
        engine = self._make_engine(backend="auto")
        findings = [Finding(id="1", severity=Severity.HIGH, title="f1")]
        scanner = MockScanner(
            "bandit", findings=findings, available=True,
            container_image="ghcr.io/huntridge-labs/argus/scanner-bandit:0.8.0",
        )
        engine.register_scanner(scanner)

        # Simulate Docker available
        monkeypatch.setattr(engine, "_is_docker_available", lambda: True)
        monkeypatch.setattr(
            engine, "_run_in_container",
            lambda s, p, c: ScanResult(
                scanner=s.name, findings=s._findings,
                metadata={"execution": "container"},
            ),
        )

        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1
        # Should have used container, not local scan
        assert scanner.scan_called_with is None
        assert summary.results[0].metadata.get("execution") == "container"

    def test_auto_backend_falls_back_to_local_no_image(self):
        """auto backend falls back to local when no container image is defined."""
        engine = self._make_engine(backend="auto")
        findings = [Finding(id="1", severity=Severity.HIGH, title="f1")]
        scanner = MockScanner(
            "bandit", findings=findings, available=True,
            container_image="",
        )
        engine.register_scanner(scanner)

        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1
        # Should have used local scan (no container image available)
        assert scanner.scan_called_with is not None

    def test_auto_backend_falls_back_to_local_no_docker(self, monkeypatch):
        """auto backend falls back to local when Docker is not available."""
        engine = self._make_engine(backend="auto")
        findings = [Finding(id="1", severity=Severity.HIGH, title="f1")]
        scanner = MockScanner(
            "bandit", findings=findings, available=True,
            container_image="ghcr.io/huntridge-labs/argus/scanner-bandit:0.8.0",
        )
        engine.register_scanner(scanner)

        monkeypatch.setattr(engine, "_is_docker_available", lambda: False)

        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1
        # Docker unavailable, should fall back to local
        assert scanner.scan_called_with is not None


class TestFailFast:
    """Test --fail-fast abort-on-first-failure behavior."""

    def _make_engine(self):
        data = {"scanners": {"a": {"enabled": True}, "b": {"enabled": True}}}
        return ArgusEngine(ArgusConfig.from_dict(data))

    def test_fail_fast_stops_after_first_failure(self):
        engine = self._make_engine()

        class FailingScanner:
            name = "a"
            def scan(self, path, config=None):
                raise RuntimeError("boom")
            def is_available(self):
                return True
            def install_command(self):
                return None

        good = MockScanner("b", findings=[
            Finding(id="1", severity=Severity.LOW, title="f1"),
        ])
        engine.register_scanner(FailingScanner())
        engine.register_scanner(good)

        summary = engine.run(fail_fast=True, parallel=False)
        # Scanner "a" produces a failure row (recorded for visibility)
        # then the loop breaks before running "b". No silent drop.
        assert len(summary.results) == 1
        failed = summary.results[0]
        assert failed.scanner == "a"
        assert failed.metadata.get("execution_failed") is True
        assert "boom" in failed.metadata.get("execution_failure_reason", "")
        assert good.scan_called_with is None

    def test_without_fail_fast_continues_after_failure(self):
        engine = self._make_engine()

        class FailingScanner:
            name = "a"
            def scan(self, path, config=None):
                raise RuntimeError("boom")
            def is_available(self):
                return True
            def install_command(self):
                return None

        good = MockScanner("b", findings=[
            Finding(id="1", severity=Severity.LOW, title="f1"),
        ])
        engine.register_scanner(FailingScanner())
        engine.register_scanner(good)

        summary = engine.run(fail_fast=False)
        # Both scanners present in canonical results: "a" as a
        # failure row, "b" as a normal success row.
        assert len(summary.results) == 2
        assert good.scan_called_with is not None
        by_name = {r.scanner: r for r in summary.results}
        assert by_name["a"].metadata.get("execution_failed") is True
        assert by_name["b"].metadata.get("execution_failed") is None


class TestParallelExecution:
    """Test parallel scanner execution."""

    def _make_engine(self, count=3):
        scanners = {f"s{i}": {"enabled": True} for i in range(count)}
        data = {"scanners": scanners}
        return ArgusEngine(ArgusConfig.from_dict(data))

    def test_parallel_runs_all_scanners(self):
        engine = self._make_engine(3)
        for i in range(3):
            engine.register_scanner(MockScanner(f"s{i}", findings=[
                Finding(id=str(i), severity=Severity.LOW, title=f"f{i}"),
            ]))

        summary = engine.run(parallel=True)
        assert len(summary.results) == 3

    def test_parallel_failure_surfaces_as_failure_row(self):
        """Regression for ADR-016: a scanner that raises in parallel mode
        produces a ScanResult with execution_failed metadata, not a
        silent drop. This is the bug behind ``lint-dockerfile`` going
        missing from results when hadolint isn't installed locally —
        custom scan() implementations that raise FileNotFoundError used
        to disappear from canonical results entirely.
        """
        engine = self._make_engine(2)  # config has scanners s0, s1

        class FailingScanner:
            name = "s0"
            def scan(self, path, config=None):
                raise FileNotFoundError(2, "No such file", "broken-tool")
            def is_available(self):
                return True
            def install_command(self):
                return None

        good = MockScanner("s1", findings=[
            Finding(id="1", severity=Severity.LOW, title="f"),
        ])
        engine.register_scanner(FailingScanner())
        engine.register_scanner(good)

        summary = engine.run(parallel=True)
        assert len(summary.results) == 2
        by_name = {r.scanner: r for r in summary.results}
        assert by_name["s0"].metadata.get("execution_failed") is True
        assert "FileNotFoundError" in by_name["s0"].metadata.get(
            "execution_failure_reason", "",
        )
        assert by_name["s1"].metadata.get("execution_failed") is None

    def test_parallel_faster_than_sequential(self):
        """Parallel should be faster when scanners have I/O wait."""
        import time as time_mod

        engine = self._make_engine(3)

        class SlowMockScanner:
            def __init__(self, name):
                self.name = name
            def scan(self, path, config=None):
                time_mod.sleep(0.2)
                return ScanResult(scanner=self.name, findings=[
                    Finding(id="1", severity=Severity.LOW, title="f"),
                ])
            def is_available(self):
                return True
            def install_command(self):
                return None

        for i in range(3):
            engine.register_scanner(SlowMockScanner(f"s{i}"))

        start = time_mod.monotonic()
        summary = engine.run(parallel=True)
        parallel_time = time_mod.monotonic() - start

        assert len(summary.results) == 3
        # 3 scanners x 0.2s each = 0.6s sequential, <0.5s parallel
        assert parallel_time < 0.5

    def test_sequential_fallback(self):
        engine = self._make_engine(2)
        for i in range(2):
            engine.register_scanner(MockScanner(f"s{i}", findings=[
                Finding(id=str(i), severity=Severity.LOW, title=f"f{i}"),
            ]))

        summary = engine.run(parallel=False)
        assert len(summary.results) == 2

    def test_parallel_records_duration_ms_in_metadata(self):
        engine = self._make_engine(3)
        for i in range(3):
            engine.register_scanner(MockScanner(f"s{i}", findings=[
                Finding(id=str(i), severity=Severity.LOW, title=f"f{i}"),
            ]))

        summary = engine.run(parallel=True)
        assert len(summary.results) == 3
        for result in summary.results:
            assert "duration_ms" in result.metadata
            assert isinstance(result.metadata["duration_ms"], int)
            assert result.metadata["duration_ms"] >= 0

    def test_single_scanner_runs_sequential(self):
        """Single scanner skips thread pool overhead."""
        data = {"scanners": {"only": {"enabled": True}}}
        engine = ArgusEngine(ArgusConfig.from_dict(data))
        scanner = MockScanner("only", findings=[
            Finding(id="1", severity=Severity.LOW, title="f1"),
        ])
        engine.register_scanner(scanner)

        summary = engine.run(parallel=True)
        assert len(summary.results) == 1
        assert scanner.scan_called_with is not None


class TestTimeout:
    """Test per-scanner timeout enforcement."""

    def _make_engine(self):
        data = {"scanners": {"slow": {"enabled": True}}}
        return ArgusEngine(ArgusConfig.from_dict(data))

    def test_timeout_raises_on_slow_scanner(self):
        import time

        engine = self._make_engine()

        class SlowScanner:
            name = "slow"
            def scan(self, path, config=None):
                time.sleep(5)
                return ScanResult(scanner=self.name)
            def is_available(self):
                return True
            def install_command(self):
                return None

        engine.register_scanner(SlowScanner())
        summary = engine.run(timeout=1)
        # Timeout surfaces as a failure row, not a silent drop.
        assert len(summary.results) == 1
        assert summary.results[0].metadata.get("execution_failed") is True

    def test_no_timeout_allows_completion(self):
        engine = self._make_engine()
        scanner = MockScanner("slow", findings=[
            Finding(id="1", severity=Severity.LOW, title="f1"),
        ])
        engine.register_scanner(scanner)

        summary = engine.run(timeout=None)
        assert len(summary.results) == 1


class TestImageDigest:
    """Test _get_image_digest() subprocess interactions."""

    def _make_engine(self):
        return ArgusEngine(ArgusConfig.from_dict({}))

    def test_digest_from_repo_digest(self, monkeypatch):
        engine = self._make_engine()
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="registry/image@sha256:abc123\n",
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)

        digest = engine._get_image_digest("registry/image:latest")
        assert digest == "sha256:abc123"

    def test_digest_fallback_to_image_id(self, monkeypatch):
        engine = self._make_engine()
        calls = []

        def mock_run(*args, **kwargs):
            calls.append(args[0])
            if len(calls) == 1:
                return subprocess.CompletedProcess(
                    args=[], returncode=1, stdout="", stderr="",
                )
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout="sha256:localid\n",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)

        digest = engine._get_image_digest("myimage:dev")
        assert digest == "sha256:localid"
        assert len(calls) == 2

    def test_digest_timeout_returns_unknown(self, monkeypatch):
        engine = self._make_engine()

        def mock_run(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="docker", timeout=10)

        monkeypatch.setattr(subprocess, "run", mock_run)

        assert engine._get_image_digest("image:latest") == "unknown"

    def test_digest_failure_returns_unknown(self, monkeypatch):
        engine = self._make_engine()

        def mock_run(*args, **kwargs):
            raise OSError("Docker not found")

        monkeypatch.setattr(subprocess, "run", mock_run)

        assert engine._get_image_digest("image:latest") == "unknown"


class TestPullImage:
    """Test _pull_image() with various pull policies."""

    def _make_engine(self, pull_policy="if-not-present"):
        data = {"execution": {"pull_policy": pull_policy}}
        return ArgusEngine(ArgusConfig.from_dict(data))

    def test_pull_never_policy_found_locally(self, monkeypatch):
        engine = self._make_engine(pull_policy="never")
        mock_result = subprocess.CompletedProcess(args=[], returncode=0)
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)

        assert engine._pull_image("myimage:latest") is True

    def test_pull_never_policy_not_found(self, monkeypatch):
        engine = self._make_engine(pull_policy="never")
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="",
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)

        assert engine._pull_image("myimage:latest") is False

    def test_pull_if_not_present_found_locally(self, monkeypatch):
        engine = self._make_engine(pull_policy="if-not-present")
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="sha256:abc\n",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)

        assert engine._pull_image("myimage:latest") is True
        # Should inspect but never call docker pull
        assert not any("pull" in str(c) for c in calls if isinstance(c, list) and "pull" in c)

    def test_pull_if_not_present_pulls_when_missing(self, monkeypatch):
        engine = self._make_engine(pull_policy="if-not-present")
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            # First call: docker image inspect -> not found
            if "inspect" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=1, stdout="", stderr="",
                )
            # Pull call -> success
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="Pulled\n", stderr="",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)

        assert engine._pull_image("myimage:latest") is True
        pull_calls = [c for c in calls if isinstance(c, list) and "pull" in c]
        assert len(pull_calls) >= 1

    def test_pull_always_policy_pulls(self, monkeypatch):
        engine = self._make_engine(pull_policy="always")
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="sha256:abc\n", stderr="",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)

        assert engine._pull_image("myimage:latest") is True
        # Should call docker pull directly (no inspect first)
        first_cmd = calls[0]
        assert "pull" in first_cmd

    def test_pull_arm64_fallback(self, monkeypatch):
        engine = self._make_engine(pull_policy="always")
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            # First pull fails, second (with --platform) succeeds
            if "pull" in cmd and "--platform" not in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=1, stdout="", stderr="arch mismatch",
                )
            if "--platform" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="Pulled\n", stderr="",
                )
            # Digest inspection
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="sha256:abc\n",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)

        assert engine._pull_image("myimage:latest") is True
        platform_calls = [
            c for c in calls
            if isinstance(c, list) and "--platform" in c
        ]
        assert len(platform_calls) == 1


class TestRunInContainer:
    """Test _run_in_container() Docker execution path."""

    def _make_engine(self):
        data = {"execution": {"backend": "docker"}}
        return ArgusEngine(ArgusConfig.from_dict(data))

    def _make_scanner(self, **overrides):
        scanner = MockScanner(
            name=overrides.get("name", "test-scanner"),
            container_image=overrides.get("container_image", "img:latest"),
        )
        if "container_entrypoint" in overrides:
            scanner.container_entrypoint = overrides["container_entrypoint"]
        if "parse_results" in overrides:
            scanner.parse_results = overrides["parse_results"]
        return scanner

    def test_container_produces_output_file(self, monkeypatch, tmp_path):
        engine = self._make_engine()
        expected_findings = [
            Finding(id="1", severity=Severity.HIGH, title="vuln"),
        ]
        scanner = self._make_scanner(
            parse_results=lambda f: expected_findings,
        )

        monkeypatch.setattr(engine, "_pull_image", lambda img: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda img: "sha256:abc")

        def mock_run(cmd, **kwargs):
            # Write a fake result file into the output volume
            for i, arg in enumerate(cmd):
                if arg == "/output" and i > 0 and cmd[i - 1] == "-v":
                    break
            # Extract output dir from -v bind mount
            for i, arg in enumerate(cmd):
                if ":/output" in str(arg):
                    host_dir = arg.split(":")[0]
                    Path(host_dir).joinpath("results.json").write_text("{}")
                    break
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr="",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)

        result = engine._run_in_container(scanner, "/src", {})
        assert result.scanner == "test-scanner"
        assert len(result.findings) == 1
        assert result.metadata["execution"] == "container"

    def test_container_captures_stdout_when_no_files(self, monkeypatch):
        engine = self._make_engine()
        captured_file = {}

        def mock_parse(filepath):
            captured_file["path"] = filepath
            return [Finding(id="1", severity=Severity.LOW, title="from stdout")]

        scanner = self._make_scanner(parse_results=mock_parse)

        monkeypatch.setattr(engine, "_pull_image", lambda img: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda img: "sha256:abc")

        def mock_run(cmd, **kwargs):
            return subprocess.CompletedProcess(
                args=cmd, returncode=0,
                stdout="scanner output on stdout\n", stderr="",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)

        result = engine._run_in_container(scanner, "/src", {})
        assert result.findings[0].title == "from stdout"
        assert captured_file["path"].name == "stdout.txt"

    def test_container_output_dir_is_world_writable(self, monkeypatch):
        """Regression: scanners running as USER non-root (uid 1000)
        couldn't write /output/results.json on hosts with uid != 1000
        because Python's TemporaryDirectory creates dirs mode 0o700.
        Engine now chmods the dir 0o777 right after creation."""
        engine = self._make_engine()
        scanner = self._make_scanner()

        monkeypatch.setattr(engine, "_pull_image", lambda img: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda img: "sha256:abc")

        captured_mode = {}

        def mock_run(cmd, **_kwargs):
            # The chmod happens before docker run, so by the time we're
            # invoked the host-side temp dir already has the new mode.
            for i, arg in enumerate(cmd):
                if ":/output" in str(arg):
                    host_dir = arg.split(":")[0]
                    captured_mode["mode"] = os.stat(host_dir).st_mode & 0o777
                    Path(host_dir).joinpath("results.json").write_text("{}")
                    break
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr="",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)

        engine._run_in_container(scanner, "/src", {})
        # 0o777 means rwx for owner, group, other — every container
        # uid can write to /output regardless of its image's USER.
        assert captured_mode["mode"] == 0o777

    def test_container_no_output_marks_execution_failed(self, monkeypatch):
        """Empty result_files + no stdout means the container ran but
        produced nothing. Mark the ScanResult so reporters and the
        --fail-on-scanner-error gate can surface it instead of silently
        rolling it up as an empty PASS."""
        engine = self._make_engine()
        scanner = self._make_scanner()

        monkeypatch.setattr(engine, "_pull_image", lambda img: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda img: "sha256:abc")

        def mock_run(cmd, **_kwargs):
            # Container exits 13 (permission denied) without writing
            # anything to /output — the exact bug in the user report.
            return subprocess.CompletedProcess(
                args=cmd, returncode=13, stdout="",
                stderr="cannot open /output/results.json: permission denied",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)

        result = engine._run_in_container(scanner, "/src", {})
        assert result.findings == []
        assert result.metadata.get("execution_failed") is True
        # Reason carries the stderr for the user — they shouldn't have
        # to bump the log level to find out why.
        reason = result.metadata.get("execution_failure_reason", "")
        assert "permission denied" in reason
        assert "exit=13" in reason

    def test_container_with_output_does_not_mark_execution_failed(self, monkeypatch):
        """Successful container runs must not get the failure marker."""
        engine = self._make_engine()
        scanner = self._make_scanner(parse_results=lambda f: [])

        monkeypatch.setattr(engine, "_pull_image", lambda img: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda img: "sha256:abc")

        def mock_run(cmd, **_kwargs):
            for i, arg in enumerate(cmd):
                if ":/output" in str(arg):
                    Path(arg.split(":")[0]).joinpath("results.json").write_text("[]")
                    break
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr="",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)

        result = engine._run_in_container(scanner, "/src", {})
        assert "execution_failed" not in result.metadata

    def test_raw_output_dir_persists_per_scanner_files(self, monkeypatch, tmp_path):
        """When ``raw_output_dir`` is set, the engine copies each
        scanner's raw output (results.json / *.sarif / stdout.txt)
        into ``<raw_output_dir>/<scanner.name>/`` before the tempdir
        is wiped. Mirrors the container-scan flow's ``raw/`` artifact
        preservation so source scans aren't an inconsistent
        second-class case."""
        engine = self._make_engine()
        scanner = self._make_scanner(parse_results=lambda f: [])
        engine._raw_output_root = str(tmp_path / "raw")

        monkeypatch.setattr(engine, "_pull_image", lambda img: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda img: "sha256:abc")

        def mock_run(cmd, **_kwargs):
            for i, arg in enumerate(cmd):
                if ":/output" in str(arg):
                    Path(arg.split(":")[0]).joinpath("results.json").write_text(
                        '{"findings": []}'
                    )
                    break
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr="",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)
        engine._run_in_container(scanner, "/src", {})

        # File landed at <raw_output_root>/<scanner_name>/results.json
        # — the per-scanner subdir keeps multi-scanner runs from
        # colliding on common filenames.
        persisted = tmp_path / "raw" / scanner.name / "results.json"
        assert persisted.exists()
        # Contents survived intact.
        assert "findings" in persisted.read_text()

    def test_raw_output_dir_none_does_not_persist_files(
        self, monkeypatch, tmp_path,
    ):
        """Default behavior — ``raw_output_dir`` unset — leaves no
        per-scanner artifacts on disk after the run. Confirms the
        copy step is opt-in, not always-on."""
        engine = self._make_engine()
        scanner = self._make_scanner(parse_results=lambda f: [])
        # Explicitly None (the default).
        engine._raw_output_root = None

        monkeypatch.setattr(engine, "_pull_image", lambda img: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda img: "sha256:abc")

        def mock_run(cmd, **_kwargs):
            for i, arg in enumerate(cmd):
                if ":/output" in str(arg):
                    Path(arg.split(":")[0]).joinpath("results.json").write_text("{}")
                    break
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr="",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)
        engine._run_in_container(scanner, "/src", {})

        # tmp_path is otherwise untouched.
        assert list(tmp_path.iterdir()) == []

    def test_raw_output_persists_stdout_fallback(self, monkeypatch, tmp_path):
        """Some scanners write to stdout instead of a file (e.g.
        ClamAV). The engine captures that as ``stdout.txt`` in the
        per-scanner tempdir; raw-output preservation should pick it
        up the same way it picks up regular result files."""
        engine = self._make_engine()
        scanner = self._make_scanner(parse_results=lambda f: [])
        engine._raw_output_root = str(tmp_path / "raw")

        monkeypatch.setattr(engine, "_pull_image", lambda img: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda img: "sha256:abc")

        def mock_run(cmd, **_kwargs):
            return subprocess.CompletedProcess(
                args=cmd, returncode=0,
                stdout="scanner output line 1\nscanner output line 2\n",
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)
        engine._run_in_container(scanner, "/src", {})

        persisted = tmp_path / "raw" / scanner.name / "stdout.txt"
        assert persisted.exists()
        assert "scanner output line" in persisted.read_text()

    def test_raw_output_skips_zero_byte_files(self, monkeypatch, tmp_path):
        """0-byte files are explicit failure signals upstream
        (``_validate_scanner_output`` rejects them in the container
        sub-scanners). Don't persist them — making known-broken
        output look authoritative on disk would mislead anyone
        triaging from the saved artifacts."""
        engine = self._make_engine()
        scanner = self._make_scanner(parse_results=lambda f: [])
        engine._raw_output_root = str(tmp_path / "raw")

        monkeypatch.setattr(engine, "_pull_image", lambda img: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda img: "sha256:abc")

        def mock_run(cmd, **_kwargs):
            for i, arg in enumerate(cmd):
                if ":/output" in str(arg):
                    Path(arg.split(":")[0]).joinpath("results.json").touch()
                    break
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr="",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)
        engine._run_in_container(scanner, "/src", {})

        target_dir = tmp_path / "raw" / scanner.name
        # Either no dir created or empty — never a 0-byte stub.
        if target_dir.exists():
            assert not list(target_dir.iterdir())

    def test_container_custom_entrypoint(self, monkeypatch):
        engine = self._make_engine()
        scanner = self._make_scanner(container_entrypoint="/bin/custom")
        captured_cmd = {}

        monkeypatch.setattr(engine, "_pull_image", lambda img: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda img: "sha256:abc")

        def mock_run(cmd, **kwargs):
            captured_cmd["cmd"] = cmd
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr="",
            )

        monkeypatch.setattr(subprocess, "run", mock_run)

        engine._run_in_container(scanner, "/src", {})
        assert "--entrypoint" in captured_cmd["cmd"]
        ep_idx = captured_cmd["cmd"].index("--entrypoint")
        assert captured_cmd["cmd"][ep_idx + 1] == "/bin/custom"


class TestExclusions:
    """Test the exclusions module — path filtering and ignore file parsing."""

    def _make_findings(self, locations):
        return [
            Finding(
                id=str(i), severity=Severity.LOW,
                title=f"f{i}", location=loc,
            )
            for i, loc in enumerate(locations)
        ]

    def test_filter_removes_matching_paths(self):
        from argus.core.exclusions import filter_findings
        findings = self._make_findings([
            "src/main.py",
            "tests/test_main.py",
            "src/utils.py",
        ])
        kept, excluded = filter_findings(findings, ["tests"])
        assert excluded == 1
        assert len(kept) == 2

    def test_filter_empty_patterns_returns_all(self):
        from argus.core.exclusions import filter_findings
        findings = self._make_findings(["a.py", "b.py", "c.py"])
        kept, excluded = filter_findings(findings, [])
        assert excluded == 0
        assert len(kept) == 3

    def test_filter_multiple_patterns(self):
        from argus.core.exclusions import filter_findings
        findings = self._make_findings([
            "src/main.py",
            "vendor/lib.py",
            "tests/test_main.py",
            "docs/guide.md",
        ])
        kept, excluded = filter_findings(findings, ["vendor", "tests"])
        assert excluded == 2
        assert len(kept) == 2

    def test_filter_glob_patterns(self):
        from argus.core.exclusions import filter_findings
        findings = self._make_findings([
            "src/main.py",
            "src/main.pyc",
            "build/output.js",
        ])
        kept, excluded = filter_findings(findings, ["*.pyc", "build"])
        assert excluded == 2
        assert len(kept) == 1

    def test_build_exclusion_set_includes_builtins(self):
        from argus.core.exclusions import build_exclusion_set
        patterns = build_exclusion_set(scan_path="/nonexistent")
        assert "node_modules" in patterns
        assert ".git" in patterns
        assert "__pycache__" in patterns

    def test_build_exclusion_set_adds_cli_excludes(self):
        from argus.core.exclusions import build_exclusion_set
        patterns = build_exclusion_set(
            scan_path="/nonexistent",
            cli_excludes="mydir,other",
        )
        assert "mydir" in patterns
        assert "other" in patterns

    def test_build_exclusion_set_reads_gitignore(self, tmp_path):
        from argus.core.exclusions import build_exclusion_set
        (tmp_path / ".gitignore").write_text("*.log\nsecrets/\n")
        patterns = build_exclusion_set(scan_path=str(tmp_path))
        assert "*.log" in patterns
        assert "secrets" in patterns

    def test_is_excluded_substring_match(self):
        from argus.core.exclusions import is_excluded
        assert is_excluded("tests/test_main.py", ["tests"])
        assert not is_excluded("src/main.py", ["tests"])

    def test_is_excluded_glob_match(self):
        from argus.core.exclusions import is_excluded
        assert is_excluded("src/cache.pyc", ["*.pyc"])
        assert not is_excluded("src/main.py", ["*.pyc"])


class TestToolConfigAutoDiscovery:
    """Engine should auto-discover per-scanner config files and pass them through."""

    def _make_engine(self, scanners_config=None):
        data = {"scanners": scanners_config or {}}
        return ArgusEngine(ArgusConfig.from_dict(data))

    def test_bandit_picks_up_dot_bandit_via_engine(self, tmp_path):
        (tmp_path / ".bandit").write_text("[bandit]\nskips = [\"B101\"]\n")
        engine = self._make_engine({"bandit": {"enabled": True}})
        engine.register_scanner(MockScanner("bandit"))

        engine.run(path=str(tmp_path))

        resolutions = engine._last_resolutions
        assert len(resolutions) == 1
        assert resolutions[0].scanner == "bandit"
        assert resolutions[0].source == "discovered"
        assert resolutions[0].path.endswith(".bandit")

    def test_explicit_config_file_wins_over_autodiscovery(self, tmp_path):
        (tmp_path / ".bandit").write_text("[bandit]\n")
        (tmp_path / "custom.yaml").write_text("skips = []\n")
        engine = self._make_engine(
            {"bandit": {"enabled": True, "config_file": "custom.yaml"}},
        )
        engine.register_scanner(MockScanner("bandit"))

        engine.run(path=str(tmp_path))

        resolutions = engine._last_resolutions
        assert resolutions[0].source == "explicit"
        assert resolutions[0].path == "custom.yaml"

    def test_no_config_file_when_nothing_present(self, tmp_path):
        engine = self._make_engine({"bandit": {"enabled": True}})
        engine.register_scanner(MockScanner("bandit"))

        engine.run(path=str(tmp_path))

        resolutions = engine._last_resolutions
        assert resolutions[0].source == "none"

    def test_discovered_path_is_relative_to_scan_root(self, tmp_path):
        (tmp_path / ".bandit").write_text("[bandit]\n")
        engine = self._make_engine({"bandit": {"enabled": True}})
        scanner = MockScanner("bandit")
        engine.register_scanner(scanner)

        engine.run(path=str(tmp_path))

        # The scanner receives config_file relative to the scan root so
        # container wrappers can prepend /workspace/ correctly.
        _, config = scanner.scan_called_with
        assert config["config_file"] == ".bandit"


class TestNoDefaultExcludes:
    """use_default_excludes=False must drop builtins + gitignore patterns."""

    def _make_engine(self, scanners_config=None):
        data = {"scanners": scanners_config or {}}
        return ArgusEngine(ArgusConfig.from_dict(data))

    def test_drops_builtins_and_gitignore_when_disabled(self, tmp_path):
        (tmp_path / ".gitignore").write_text("*.log\n")
        engine = self._make_engine({"bandit": {"enabled": True}})
        scanner = MockScanner("bandit")
        engine.register_scanner(scanner)

        engine.run(
            path=str(tmp_path),
            exclude="mydir",
            use_default_excludes=False,
        )

        _, config = scanner.scan_called_with
        excludes = config.get("exclude", "").split(",")
        assert "node_modules" not in excludes
        assert "*.log" not in excludes
        assert "mydir" in excludes

    def test_defaults_preserved_by_default(self, tmp_path):
        engine = self._make_engine({"bandit": {"enabled": True}})
        scanner = MockScanner("bandit")
        engine.register_scanner(scanner)

        engine.run(path=str(tmp_path), exclude="mydir")

        _, config = scanner.scan_called_with
        excludes = config.get("exclude", "").split(",")
        assert "node_modules" in excludes
        assert "mydir" in excludes


class TestEngineSbomMode:
    """engine.run(sbom_path=...) threads the path and filters to sbom-capable scanners."""

    def _make_engine(self, scanners_config=None):
        data = {"scanners": scanners_config or {}}
        return ArgusEngine(ArgusConfig.from_dict(data))

    def _make_sbom_scanner(self, name: str):
        scanner = MockScanner(name)
        scanner.supports_sbom = True
        return scanner

    def test_filters_to_sbom_capable_scanners(self, tmp_path):
        sbom = tmp_path / "sbom.json"
        sbom.write_text('{"bomFormat": "CycloneDX"}')

        engine = self._make_engine({
            "osv": {"enabled": True},
            "bandit": {"enabled": True},
        })
        sbom_capable = self._make_sbom_scanner("osv")
        not_capable = MockScanner("bandit")  # supports_sbom = False by default
        engine.register_scanner(sbom_capable)
        engine.register_scanner(not_capable)

        engine.run(sbom_path=str(sbom))

        assert sbom_capable.scan_called_with is not None
        assert not_capable.scan_called_with is None

    def test_auto_enables_sbom_scanners_regardless_of_config(self, tmp_path):
        sbom = tmp_path / "sbom.json"
        sbom.write_text('{"bomFormat": "CycloneDX"}')

        # osv is explicitly DISABLED in argus.yml; --sbom should override.
        engine = self._make_engine({"osv": {"enabled": False}})
        osv = self._make_sbom_scanner("osv")
        engine.register_scanner(osv)

        engine.run(sbom_path=str(sbom))

        assert osv.scan_called_with is not None

    def test_passes_sbom_path_via_config(self, tmp_path):
        sbom = tmp_path / "sbom.json"
        sbom.write_text("{}")

        engine = self._make_engine({"osv": {"enabled": True}})
        osv = self._make_sbom_scanner("osv")
        engine.register_scanner(osv)

        engine.run(sbom_path=str(sbom))

        _, config = osv.scan_called_with
        assert config["sbom_path"] == str(sbom)
        # Mount path dedicated to /sbom/ so it can't collide with workspace files
        assert config["sbom_mount_path"].startswith("/sbom/")
        assert config["sbom_mount_path"].endswith("sbom.json")

    def test_named_scanner_without_sbom_support_is_dropped(self, tmp_path, caplog):
        sbom = tmp_path / "sbom.json"
        sbom.write_text("{}")

        engine = self._make_engine({"bandit": {"enabled": True}})
        not_capable = MockScanner("bandit")
        engine.register_scanner(not_capable)

        with caplog.at_level("WARNING"):
            engine.run(scanner_names=["bandit"], sbom_path=str(sbom))

        assert not_capable.scan_called_with is None
        assert any("does not support SBOM" in msg for msg in caplog.messages)

    # --- sbom_format → canonical extension mapping tests ---

    def test_sbom_format_spdx_json_uses_canonical_extension(self, tmp_path):
        sbom = tmp_path / "my-sbom.json"
        sbom.write_text("{}")

        engine = self._make_engine({"osv": {"enabled": True}})
        osv = self._make_sbom_scanner("osv")
        engine.register_scanner(osv)

        engine.run(sbom_path=str(sbom), sbom_format="spdx-json")

        _, config = osv.scan_called_with
        assert config["sbom_mount_path"] == "/sbom/sbom.spdx.json"

    def test_sbom_format_cyclonedx_json_uses_canonical_extension(self, tmp_path):
        sbom = tmp_path / "my-sbom.json"
        sbom.write_text("{}")

        engine = self._make_engine({"osv": {"enabled": True}})
        osv = self._make_sbom_scanner("osv")
        engine.register_scanner(osv)

        engine.run(sbom_path=str(sbom), sbom_format="cyclonedx-json")

        _, config = osv.scan_called_with
        assert config["sbom_mount_path"] == "/sbom/sbom.cdx.json"

    def test_sbom_format_cyclonedx_xml_uses_canonical_extension(self, tmp_path):
        sbom = tmp_path / "my-sbom.xml"
        sbom.write_text("<bom/>")

        engine = self._make_engine({"osv": {"enabled": True}})
        osv = self._make_sbom_scanner("osv")
        engine.register_scanner(osv)

        engine.run(sbom_path=str(sbom), sbom_format="cyclonedx-xml")

        _, config = osv.scan_called_with
        assert config["sbom_mount_path"] == "/sbom/sbom.cdx.xml"

    def test_sbom_format_spdx_tv_uses_canonical_extension(self, tmp_path):
        sbom = tmp_path / "my-sbom.txt"
        sbom.write_text("SPDXVersion: SPDX-2.3")

        engine = self._make_engine({"osv": {"enabled": True}})
        osv = self._make_sbom_scanner("osv")
        engine.register_scanner(osv)

        engine.run(sbom_path=str(sbom), sbom_format="spdx-tv")

        _, config = osv.scan_called_with
        assert config["sbom_mount_path"] == "/sbom/sbom.spdx"

    # --- Multi-suffix fallback tests ---

    def test_multi_suffix_path_preserves_compound_extension(self, tmp_path):
        """foo.spdx.json should preserve .spdx.json, not collapse to .json."""
        sbom = tmp_path / "foo.spdx.json"
        sbom.write_text("{}")

        engine = self._make_engine({"osv": {"enabled": True}})
        osv = self._make_sbom_scanner("osv")
        engine.register_scanner(osv)

        # No sbom_format — should fall back to file extension
        engine.run(sbom_path=str(sbom))

        _, config = osv.scan_called_with
        assert config["sbom_mount_path"] == "/sbom/sbom.spdx.json"

    def test_multi_suffix_cdx_path_preserves_compound_extension(self, tmp_path):
        """foo.cdx.json should preserve .cdx.json, not collapse to .json."""
        sbom = tmp_path / "foo.cdx.json"
        sbom.write_text("{}")

        engine = self._make_engine({"osv": {"enabled": True}})
        osv = self._make_sbom_scanner("osv")
        engine.register_scanner(osv)

        engine.run(sbom_path=str(sbom))

        _, config = osv.scan_called_with
        assert config["sbom_mount_path"] == "/sbom/sbom.cdx.json"

    def test_single_suffix_path_uses_that_suffix(self, tmp_path):
        """foo.json should use .json when no sbom_format provided."""
        sbom = tmp_path / "foo.json"
        sbom.write_text("{}")

        engine = self._make_engine({"osv": {"enabled": True}})
        osv = self._make_sbom_scanner("osv")
        engine.register_scanner(osv)

        engine.run(sbom_path=str(sbom))

        _, config = osv.scan_called_with
        assert config["sbom_mount_path"] == "/sbom/sbom.json"

    # --- sbom_format validation tests ---

    def test_unknown_sbom_format_logs_warning(self, tmp_path, caplog):
        """Unknown sbom_format should log a warning and fall back to extension."""
        sbom = tmp_path / "foo.spdx.json"
        sbom.write_text("{}")

        engine = self._make_engine({"osv": {"enabled": True}})
        osv = self._make_sbom_scanner("osv")
        engine.register_scanner(osv)

        with caplog.at_level("WARNING"):
            engine.run(sbom_path=str(sbom), sbom_format="invalid-format")

        # Should have logged a warning about the unrecognized format
        assert any("Unrecognized sbom_format" in msg for msg in caplog.messages)
        assert any("invalid-format" in msg for msg in caplog.messages)

        # Should still fall back to extension-based detection
        _, config = osv.scan_called_with
        assert config["sbom_mount_path"] == "/sbom/sbom.spdx.json"

    # --- Exclusion filter bypass tests ---

    def test_exclusion_filter_skipped_in_sbom_mode(self, tmp_path, monkeypatch):
        """Exclusion filter should NOT be invoked when sbom_path is set."""
        from unittest.mock import MagicMock

        sbom = tmp_path / "sbom.json"
        sbom.write_text("{}")

        engine = self._make_engine({"osv": {"enabled": True}})
        osv = self._make_sbom_scanner("osv")
        # Add some findings that would normally be filtered
        osv._findings = [
            Finding(
                id="1", severity=Severity.HIGH, title="vuln",
                location="node_modules/bad/lib.js",  # Normally excluded
            ),
        ]
        engine.register_scanner(osv)

        # Patch filter_findings with a MagicMock to track calls
        from argus.core import exclusions
        mock_filter = MagicMock()
        monkeypatch.setattr(exclusions, "filter_findings", mock_filter)

        summary = engine.run(sbom_path=str(sbom), exclude="node_modules")

        # filter_findings should NOT have been called in SBOM mode
        mock_filter.assert_not_called()
        # Findings should still be present (not filtered)
        assert len(summary.results) == 1
        assert summary.results[0].total_count == 1


class TestToolVersionEnforcement:
    """Test local tool version verification against container-pinned versions."""

    def _make_engine(self, backend="local"):
        data = {"execution": {"backend": backend}}
        return ArgusEngine(ArgusConfig.from_dict(data))

    def _make_versioned_scanner(
        self, name="bandit", version="1.0.0", available=True,
    ):
        """Create a mock scanner with a tool_version() method."""
        scanner = MockScanner(name, available=available)
        scanner.tool_version = lambda: version
        return scanner

    def test_version_match_allows_scan(self, monkeypatch):
        """Matching versions should proceed without error."""
        engine = self._make_engine(backend="local")
        scanner = self._make_versioned_scanner("bandit", version="1.0.0")
        engine.register_scanner(scanner)

        monkeypatch.setattr(
            "argus.containers.get_expected_version",
            lambda name: "1.0.0",
        )

        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1
        assert scanner.scan_called_with is not None

    def test_version_mismatch_raises_by_default(self, monkeypatch):
        """Mismatched versions should raise RuntimeError (strict mode)."""
        engine = self._make_engine(backend="local")
        scanner = self._make_versioned_scanner("bandit", version="0.9.0")
        engine.register_scanner(scanner)

        monkeypatch.setattr(
            "argus.containers.get_expected_version",
            lambda name: "1.0.0",
        )

        # Version mismatch surfaces as a failure row instead of a
        # silent drop.
        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1
        assert summary.results[0].metadata.get("execution_failed") is True

    def test_version_mismatch_allowed_with_flag(self, monkeypatch):
        """With allow_local_versions=True, mismatch logs warning but proceeds."""
        engine = self._make_engine(backend="local")
        scanner = self._make_versioned_scanner("bandit", version="0.9.0")
        engine.register_scanner(scanner)

        monkeypatch.setattr(
            "argus.containers.get_expected_version",
            lambda name: "1.0.0",
        )

        summary = engine.run(
            scanner_names=["bandit"],
            allow_local_versions=True,
        )
        assert len(summary.results) == 1
        assert scanner.scan_called_with is not None

    def test_no_expected_version_skips_check(self, monkeypatch):
        """When no expected version exists, skip the check entirely."""
        engine = self._make_engine(backend="local")
        scanner = self._make_versioned_scanner("custom", version="2.0.0")
        engine.register_scanner(scanner)

        monkeypatch.setattr(
            "argus.containers.get_expected_version",
            lambda name: None,
        )

        summary = engine.run(scanner_names=["custom"])
        assert len(summary.results) == 1

    def test_no_tool_version_method_skips_check(self, monkeypatch):
        """Scanners without tool_version() should pass version check."""
        engine = self._make_engine(backend="local")
        scanner = MockScanner("bandit", available=True)
        engine.register_scanner(scanner)

        monkeypatch.setattr(
            "argus.containers.get_expected_version",
            lambda name: "1.0.0",
        )

        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1

    def test_tool_version_returns_none_skips_check(self, monkeypatch):
        """If tool_version() returns None, skip the check."""
        engine = self._make_engine(backend="local")
        scanner = self._make_versioned_scanner("bandit", version=None)
        scanner.tool_version = lambda: None
        engine.register_scanner(scanner)

        monkeypatch.setattr(
            "argus.containers.get_expected_version",
            lambda name: "1.0.0",
        )

        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1

    def test_auto_backend_local_fallback_checks_version(self, monkeypatch):
        """auto backend falling back to local should still check version."""
        engine = self._make_engine(backend="auto")
        scanner = self._make_versioned_scanner("bandit", version="0.9.0")
        scanner.container_image = ""  # No container image, forces local
        engine.register_scanner(scanner)

        monkeypatch.setattr(
            "argus.containers.get_expected_version",
            lambda name: "1.0.0",
        )

        summary = engine.run(scanner_names=["bandit"])
        # Version mismatch surfaces as a failure row.
        assert len(summary.results) == 1
        assert summary.results[0].metadata.get("execution_failed") is True

    def test_tool_version_recorded_in_metadata(self, monkeypatch):
        """Tool version should be recorded in result metadata."""
        engine = self._make_engine(backend="local")
        scanner = self._make_versioned_scanner("bandit", version="1.0.0")
        engine.register_scanner(scanner)

        monkeypatch.setattr(
            "argus.containers.get_expected_version",
            lambda name: "1.0.0",
        )

        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1
        assert summary.results[0].metadata.get("tool_version") == "1.0.0"

    def test_container_execution_records_expected_version(self, monkeypatch):
        """Container execution should record version from image tag."""
        engine = self._make_engine(backend="auto")
        findings = [Finding(id="1", severity=Severity.HIGH, title="f1")]
        scanner = MockScanner(
            "bandit", findings=findings, available=True,
            container_image="ghcr.io/huntridge-labs/argus/scanner-bandit:1.0.0",
        )
        engine.register_scanner(scanner)

        monkeypatch.setattr(engine, "_is_docker_available", lambda: True)
        monkeypatch.setattr(
            engine, "_run_in_container",
            lambda s, p, c: ScanResult(
                scanner=s.name, findings=s._findings,
                metadata={"execution": "container"},
            ),
        )
        monkeypatch.setattr(
            "argus.containers.get_expected_version",
            lambda name: "1.0.0",
        )

        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1
        assert summary.results[0].metadata.get("tool_version") == "1.0.0"


class TestEngineCacheFlag:
    """Test that no_cache flag controls cache volume mounts."""

    def _make_engine(self, scanners_config=None):
        data = {}
        if scanners_config:
            data["scanners"] = scanners_config
        config = ArgusConfig.from_dict(data)
        return ArgusEngine(config)

    def test_no_cache_flag_stored(self):
        engine = self._make_engine()
        engine.run(no_cache=True)
        assert engine._no_cache is True

    def test_cache_enabled_by_default(self):
        engine = self._make_engine()
        engine.run()
        assert engine._no_cache is False


class TestEngineSilentFailureSurfacing:
    """Empty-output container runs must surface stderr + exit code loudly."""

    def _make_engine(self):
        data = {"execution": {"backend": "docker"}}
        return ArgusEngine(ArgusConfig.from_dict(data))

    def _scanner(self, **overrides):
        scanner = MockScanner(
            name=overrides.get("name", "trivy"),
            container_image="img:latest",
        )
        return scanner

    def test_empty_output_warns_with_stderr(self, monkeypatch, caplog):
        engine = self._make_engine()
        scanner = self._scanner()
        monkeypatch.setattr(engine, "_pull_image", lambda img: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda img: "sha256:abc")

        def mock_run(cmd, **kwargs):
            return subprocess.CompletedProcess(
                args=cmd, returncode=1,
                stdout="",
                stderr="FATAL: SBOM decode error: unknown scanning is not yet supported\n",
            )
        monkeypatch.setattr(subprocess, "run", mock_run)

        with caplog.at_level("WARNING"):
            engine._run_in_container(scanner, "/src", {})

        # Must include both the exit code AND the upstream stderr so
        # users can diagnose without enabling DEBUG logging.
        warnings = [r.message for r in caplog.records if r.levelname == "WARNING"]
        assert any(
            "produced no output files" in m and "exit=1" in m and
            "unknown scanning" in m
            for m in warnings
        )

    def test_empty_output_with_no_stderr_still_warns(self, monkeypatch, caplog):
        engine = self._make_engine()
        scanner = self._scanner()
        monkeypatch.setattr(engine, "_pull_image", lambda img: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda img: "sha256:abc")
        monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: (
            subprocess.CompletedProcess(cmd, returncode=2, stdout="", stderr="")
        ))

        with caplog.at_level("WARNING"):
            engine._run_in_container(scanner, "/src", {})

        msgs = [r.message for r in caplog.records if r.levelname == "WARNING"]
        assert any("no output files and no stdout" in m and "exit=2" in m for m in msgs)


class TestEngineParseResultsDictExtra:
    """parse_results can return (findings, dict) to contribute metadata + warning."""

    def _make_engine(self):
        data = {"execution": {"backend": "docker"}}
        return ArgusEngine(ArgusConfig.from_dict(data))

    def test_dict_extra_merged_and_logged(self, monkeypatch, caplog, tmp_path):
        engine = self._make_engine()

        def parse(_path):
            return ([], {"warning": "Grype source.target=unknown — 0 findings is not trustworthy"})

        scanner = MockScanner(name="grype", container_image="img:latest")
        scanner.parse_results = parse

        monkeypatch.setattr(engine, "_pull_image", lambda img: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda img: "sha256:abc")

        def mock_run(cmd, **kwargs):
            for arg in cmd:
                if ":/output" in str(arg):
                    Path(arg.split(":")[0]).joinpath("results.json").write_text("{}")
                    break
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
        monkeypatch.setattr(subprocess, "run", mock_run)

        with caplog.at_level("WARNING"):
            result = engine._run_in_container(scanner, "/src", {})

        # Warning merged into result.metadata
        assert "warning" in result.metadata
        assert "source.target=unknown" in result.metadata["warning"]
        # Warning logged at WARN so it's visible without DEBUG
        msgs = [r.message for r in caplog.records if r.levelname == "WARNING"]
        assert any("Scanner 'grype':" in m and "source.target" in m for m in msgs)
