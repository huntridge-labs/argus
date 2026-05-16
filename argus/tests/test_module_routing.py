"""Verify that CLI subcommands dispatch to the correct scanner modules.

Catches the class of bug where a fix lands in one module but the CLI
routes to a different module with the same name. These tests are fast
(no Docker, no subprocess) — they inspect imports and code structure.
"""

import ast
import inspect
import textwrap
from pathlib import Path

import pytest


class TestContainerScannerRouting:
    """Verify argus scan container routes through argus.container, not argus.scanners.container."""

    def test_cli_imports_container_engine_from_correct_module(self):
        """The CLI's container subcommand must import from argus.container."""
        from argus.cli import _cmd_container_scan
        source = inspect.getsource(_cmd_container_scan)
        assert "from argus.container" in source
        assert "from argus.scanners.container" not in source

    def test_both_modules_have_docker_fallback_in_trivy(self):
        """Both container scanner modules should have Docker fallback for trivy."""
        # The active module (used by CLI)
        from argus.container import scanner as active_mod
        trivy_src = inspect.getsource(active_mod._run_trivy)
        assert "container_runtime" in trivy_src, (
            "argus/container/scanner.py _run_trivy missing Docker fallback"
        )

        # The protocol wrapper (used by engine)
        from argus.scanners.container import ContainerScanner
        scan_src = inspect.getsource(ContainerScanner.scan) if hasattr(ContainerScanner, 'scan') else ""
        # The protocol wrapper delegates to _run_sub_scanner which has fallback
        assert "container_runtime" in inspect.getsource(ContainerScanner) or \
               "_run_sub_scanner" in scan_src, (
            "argus/scanners/container.py missing Docker fallback"
        )

    def test_no_skip_without_fallback_messages(self):
        """The old 'not installed — skipping' pattern without Docker fallback must not exist."""
        active_path = Path("argus/container/scanner.py")
        source = active_path.read_text()

        # These exact old messages meant "skip silently without trying Docker"
        assert "trivy not installed — skipping trivy scan" not in source
        assert "grype not installed — skipping grype scan" not in source

    def test_active_module_raises_on_scan_failure(self):
        """_run_trivy and _run_grype should raise RuntimeError, not return empty list."""
        from argus.container import scanner as mod
        trivy_src = inspect.getsource(mod._run_trivy)
        grype_src = inspect.getsource(mod._run_grype)

        assert "raise RuntimeError" in trivy_src, (
            "_run_trivy should raise on failure, not return []"
        )
        assert "raise RuntimeError" in grype_src, (
            "_run_grype should raise on failure, not return []"
        )

    def test_active_module_mounts_docker_socket(self):
        """Container-mode sub-scanners must mount docker.sock for local images."""
        from argus.container import scanner as mod
        trivy_src = inspect.getsource(mod._run_trivy)
        grype_src = inspect.getsource(mod._run_grype)

        assert "docker_sock" in trivy_src.lower() or "mount_docker_sock" in trivy_src
        assert "docker_sock" in grype_src.lower() or "mount_docker_sock" in grype_src


class TestDastRouting:
    """Verify ZAP/DAST engine pre-pulls images."""

    def test_dast_engine_pre_pulls_zap_image(self):
        """DastEngine must call pull_image before docker run."""
        from argus.dast.engine import DastEngine
        for method_name in ("_run_zap_scan", "_run_zap_scan_url"):
            method = getattr(DastEngine, method_name, None)
            if method is None:
                continue
            source = inspect.getsource(method)
            assert "pull_image" in source, (
                f"DastEngine.{method_name} must pre-pull ZAP image"
            )

    def test_dast_engine_uses_runtime_helper(self):
        """DastEngine must use container_runtime, not hardcoded 'docker'."""
        from argus.dast.engine import DastEngine
        source = inspect.getsource(DastEngine)
        # Should not have hardcoded docker commands outside of strings
        assert "container_runtime" in source


class TestContainerScanResultTracksErrors:
    """Verify the data model supports scanner failure reporting."""

    def test_scan_result_has_scanner_errors(self):
        from argus.container.scanner import ContainerScanResult
        r = ContainerScanResult(name="test", image_ref="img:latest")
        assert hasattr(r, "scanner_errors")
        assert r.scanner_errors == {}

    def test_summary_has_scan_failures(self):
        from argus.container.scanner import ContainerScanResult, ContainerScanSummary
        r1 = ContainerScanResult(
            name="ok", image_ref="a:1",
        )
        r2 = ContainerScanResult(
            name="bad", image_ref="b:1",
            scanner_errors={"trivy": "failed", "grype": "failed"},
        )
        summary = ContainerScanSummary(results=[r1, r2])
        assert summary.scan_failures == 1
        assert summary.container_count == 2
