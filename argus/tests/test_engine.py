"""Tests for argus.core.engine — ArgusEngine."""

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

    def test_run_skips_unavailable_scanners(self):
        engine = self._make_engine(
            scanners_config={"bandit": {"enabled": True}}
        )
        engine.register_scanner(MockScanner("bandit", available=False))

        summary = engine.run()
        assert len(summary.results) == 0

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
        assert len(summary.results) == 0


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

        # Engine catches exceptions and logs them
        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 0

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
        assert len(summary.results) == 0

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
        # Scanner "a" fails, "b" should never run (sequential mode)
        assert len(summary.results) == 0
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
        # Scanner "a" fails, "b" still runs
        assert len(summary.results) == 1
        assert good.scan_called_with is not None


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
        # Scanner should time out and produce no results
        assert len(summary.results) == 0

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

        # Engine catches exceptions — scanner produces no results
        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 0

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
        # Version mismatch should cause failure
        assert len(summary.results) == 0

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
