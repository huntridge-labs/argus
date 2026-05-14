"""Tests for argus.container.engine — ContainerEngine orchestration."""

from unittest.mock import patch, MagicMock
from pathlib import Path

import pytest

from argus.container.discovery import ContainerTarget
from argus.container.engine import ContainerEngine
from argus.container.scanner import ContainerScanResult, ContainerScanSummary
from argus.core.models import Finding, Severity


def _finding(severity=Severity.HIGH, cve=None, fid="F1"):
    return Finding(
        id=fid,
        severity=severity,
        title=f"Finding {fid}",
        cve=cve,
    )


def _target(name="app", has_dockerfile=False, tmp_path=None):
    """Create a ContainerTarget, optionally with a Dockerfile."""
    dockerfile = None
    context = None
    if has_dockerfile and tmp_path:
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine")
        context = tmp_path
    return ContainerTarget(
        name=name,
        image_ref=f"{name}:argus-scan",
        dockerfile=dockerfile,
        context=context,
    )


class TestResolveTargets:
    """Test _resolve_targets from config."""

    def test_from_explicit_images(self):
        config = {
            "containers": {
                "images": [{"image": "myapp:latest"}],
            },
        }
        engine = ContainerEngine(config)
        targets = engine._resolve_targets()
        assert len(targets) == 1
        assert targets[0].image_ref == "myapp:latest"

    def test_falls_back_to_discovery(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM alpine")
        config = {"search_paths": [str(tmp_path)]}
        engine = ContainerEngine(config)
        targets = engine._resolve_targets()
        assert len(targets) == 1

    def test_empty_config_empty_dir(self, tmp_path):
        config = {"search_paths": [str(tmp_path)]}
        engine = ContainerEngine(config)
        targets = engine._resolve_targets()
        assert targets == []


class TestScanners:
    """Test _scanners parsing."""

    def test_default_scanners(self):
        """Default mirrors the SDK Scanner path (argus/scanners/container.py).

        Both code paths must run the same attack-surface sub-scanners
        so ``argus scan container --image`` produces identical signal
        to ``argus scan --config argus.yml`` with ``scanners: [container]``.
        """
        engine = ContainerEngine({})
        assert engine._scanners() == (
            "trivy", "grype", "exposure", "services",
        )

    def test_string_scanners(self):
        engine = ContainerEngine({"scanners": "trivy, grype, syft"})
        assert engine._scanners() == ("trivy", "grype", "syft")

    def test_list_scanners(self):
        engine = ContainerEngine({"scanners": ["trivy"]})
        assert engine._scanners() == ("trivy",)

    def test_sbom_enabled_default(self):
        engine = ContainerEngine({})
        assert engine._sbom_enabled() is True

    def test_sbom_disabled(self):
        engine = ContainerEngine({"sbom": False})
        assert engine._sbom_enabled() is False


class TestRunOrchestration:
    """Test ContainerEngine.run with mocked subprocess calls."""

    @patch("argus.container.engine.scan_image")
    @patch("argus.container.engine.build_image", return_value=True)
    @patch("argus.container.engine.parse_container_config")
    @patch("argus.container.engine.check_disk_space", return_value=10 * 1024**3)
    @patch("argus.container.engine.remove_docker_image", return_value=True)
    @patch("argus.container.engine.prune_dangling_images")
    def test_run_with_build_and_scan(
        self,
        mock_prune,
        mock_remove,
        mock_disk,
        mock_parse,
        mock_build,
        mock_scan,
        tmp_path,
    ):
        target = _target("web", has_dockerfile=True, tmp_path=tmp_path)
        mock_parse.return_value = [target]
        mock_scan.return_value = ContainerScanResult(
            name="web",
            image_ref="web:argus-scan",
            combined_findings=[_finding(cve="CVE-2024-0001")],
        )

        config = {
            "containers": {
                "images": [{"image": "web:argus-scan", "dockerfile": "Dockerfile"}],
            },
        }
        engine = ContainerEngine(config)
        summary = engine.run()

        assert isinstance(summary, ContainerScanSummary)
        assert summary.container_count == 1
        assert summary.total_count == 1
        mock_build.assert_called_once_with(target)
        mock_scan.assert_called_once()

    @patch("argus.container.engine.scan_image")
    @patch("argus.container.engine.parse_container_config")
    @patch("argus.container.engine.check_disk_space", return_value=10 * 1024**3)
    def test_run_remote_image_no_build(
        self,
        mock_disk,
        mock_parse,
        mock_scan,
    ):
        target = _target("remote")  # no dockerfile
        mock_parse.return_value = [target]
        mock_scan.return_value = ContainerScanResult(
            name="remote",
            image_ref="remote:argus-scan",
        )

        engine = ContainerEngine({
            "containers": {"images": [{"image": "remote:argus-scan"}]},
        })
        summary = engine.run()
        assert summary.container_count == 1
        assert summary.build_failures == 0

    @patch("argus.container.engine.build_image", return_value=False)
    @patch("argus.container.engine.parse_container_config")
    @patch("argus.container.engine.check_disk_space", return_value=10 * 1024**3)
    def test_build_failure_recorded(
        self,
        mock_disk,
        mock_parse,
        mock_build,
        tmp_path,
    ):
        target = _target("broken", has_dockerfile=True, tmp_path=tmp_path)
        mock_parse.return_value = [target]

        engine = ContainerEngine({
            "containers": {"images": [{"image": "broken:argus-scan"}]},
        })
        summary = engine.run()
        assert summary.build_failures == 1
        assert not summary.results[0].build_success

    def test_no_targets_returns_empty_summary(self, tmp_path):
        config = {"search_paths": [str(tmp_path)]}
        engine = ContainerEngine(config)
        summary = engine.run()
        assert isinstance(summary, ContainerScanSummary)
        assert summary.container_count == 0


class TestCleanup:
    """Test cleanup behavior."""

    @patch("argus.container.engine.scan_image")
    @patch("argus.container.engine.build_image", return_value=True)
    @patch("argus.container.engine.parse_container_config")
    @patch("argus.container.engine.check_disk_space", return_value=10 * 1024**3)
    @patch("argus.container.engine.remove_docker_image", return_value=True)
    @patch("argus.container.engine.prune_dangling_images")
    def test_cleanup_removes_built_image(
        self,
        mock_prune,
        mock_remove,
        mock_disk,
        mock_parse,
        mock_build,
        mock_scan,
        tmp_path,
    ):
        target = _target("web", has_dockerfile=True, tmp_path=tmp_path)
        mock_parse.return_value = [target]
        mock_scan.return_value = ContainerScanResult(
            name="web", image_ref="web:argus-scan",
        )

        engine = ContainerEngine({
            "containers": {"images": [{"image": "web:argus-scan"}]},
            "cleanup": True,
        })
        engine.run()
        mock_remove.assert_called_with("web:argus-scan")

    @patch("argus.container.engine.scan_image")
    @patch("argus.container.engine.build_image", return_value=True)
    @patch("argus.container.engine.parse_container_config")
    @patch("argus.container.engine.check_disk_space", return_value=10 * 1024**3)
    @patch("argus.container.engine.remove_docker_image")
    @patch("argus.container.engine.prune_dangling_images")
    def test_no_cleanup_when_disabled(
        self,
        mock_prune,
        mock_remove,
        mock_disk,
        mock_parse,
        mock_build,
        mock_scan,
        tmp_path,
    ):
        target = _target("web", has_dockerfile=True, tmp_path=tmp_path)
        mock_parse.return_value = [target]
        mock_scan.return_value = ContainerScanResult(
            name="web", image_ref="web:argus-scan",
        )

        engine = ContainerEngine({
            "containers": {"images": [{"image": "web:argus-scan"}]},
            "cleanup": False,
        })
        engine.run()
        mock_remove.assert_not_called()
        mock_prune.assert_not_called()
