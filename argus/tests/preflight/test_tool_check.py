"""Unit tests for argus.preflight.tool_check."""

from __future__ import annotations

from unittest.mock import patch

from argus.preflight.report_body import ToolStatus
from argus.preflight.tool_check import (
    check_scanner_readiness,
    container_runtime_available,
    resolve_image,
    summarize,
    unavailable_names,
)


class FakeScanner:
    """Stand-in scanner used to drive readiness checks without real tools."""

    def __init__(self, available: bool = False, image: str = ""):
        self._available = available
        self.container_image = image

    def is_available(self) -> bool:
        return self._available

    def install_command(self) -> str | None:
        return "pip install fake"


class TestContainerRuntimeAvailable:
    def test_true_when_docker_found(self):
        with patch("argus.preflight.tool_check.shutil.which") as which:
            which.side_effect = lambda r: "/usr/bin/docker" if r == "docker" else None
            assert container_runtime_available() is True

    def test_false_when_nothing_found(self):
        with patch("argus.preflight.tool_check.shutil.which", return_value=None):
            assert container_runtime_available() is False


class TestResolveImage:
    def test_no_registry_passthrough(self):
        assert resolve_image("ghcr.io/foo/bar:1", "") == "ghcr.io/foo/bar:1"

    def test_empty_image_passthrough(self):
        assert resolve_image("", "my.registry") == ""

    def test_registry_replaces_host(self):
        assert resolve_image("ghcr.io/foo/bar:1", "my.registry") == "my.registry/foo/bar:1"

    def test_registry_prepends_short_ref(self):
        assert resolve_image("bandit:1", "my.registry") == "my.registry/bandit:1"


class TestCheckScannerReadiness:
    def test_local_available(self):
        registry = {"fake": lambda: FakeScanner(available=True, image="img:1")}
        with patch.dict("argus.scanners.SCANNER_REGISTRY", registry, clear=False):
            with patch("argus.containers.get_image", return_value="img:1"):
                with patch(
                    "argus.preflight.tool_check.container_runtime_available",
                    return_value=True,
                ):
                    statuses = check_scanner_readiness(["fake"])
        assert len(statuses) == 1
        assert statuses[0] == ToolStatus("fake", True, "local", network_deps=[])

    def test_container_fallback_when_local_missing(self):
        registry = {"fake": lambda: FakeScanner(available=False, image="img:1")}
        with patch.dict("argus.scanners.SCANNER_REGISTRY", registry, clear=False):
            with patch("argus.containers.get_image", return_value="img:1"):
                with patch(
                    "argus.preflight.tool_check.container_runtime_available",
                    return_value=True,
                ):
                    statuses = check_scanner_readiness(["fake"])
        assert statuses[0].available is True
        assert statuses[0].method == "container"
        assert statuses[0].image == "img:1"

    def test_missing_when_no_local_no_runtime(self):
        registry = {"fake": lambda: FakeScanner(available=False, image="img:1")}
        with patch.dict("argus.scanners.SCANNER_REGISTRY", registry, clear=False):
            with patch("argus.containers.get_image", return_value="img:1"):
                with patch(
                    "argus.preflight.tool_check.container_runtime_available",
                    return_value=False,
                ):
                    statuses = check_scanner_readiness(["fake"])
        assert statuses[0].available is False
        assert statuses[0].method == "none"

    def test_backend_local_ignores_containers(self):
        registry = {"fake": lambda: FakeScanner(available=False, image="img:1")}
        with patch.dict("argus.scanners.SCANNER_REGISTRY", registry, clear=False):
            with patch("argus.containers.get_image", return_value="img:1"):
                with patch(
                    "argus.preflight.tool_check.container_runtime_available",
                    return_value=True,
                ):
                    statuses = check_scanner_readiness(["fake"], backend="local")
        assert statuses[0].available is False
        assert statuses[0].method == "none"

    def test_unknown_scanner_is_unavailable(self):
        # Ensure the scanner is genuinely absent from both registries.
        with patch.dict("argus.scanners.SCANNER_REGISTRY", {}, clear=True):
            statuses = check_scanner_readiness(["nope"])
        assert statuses[0].available is False
        assert statuses[0].method == "none"

    def test_no_image_no_local_is_unavailable(self):
        registry = {"fake": lambda: FakeScanner(available=False, image="")}
        with patch.dict("argus.scanners.SCANNER_REGISTRY", registry, clear=False):
            with patch("argus.containers.get_image", return_value=""):
                with patch(
                    "argus.preflight.tool_check.container_runtime_available",
                    return_value=True,
                ):
                    statuses = check_scanner_readiness(["fake"])
        assert statuses[0].available is False


class TestSummarize:
    def test_buckets_mixed_statuses(self):
        statuses = [
            ToolStatus("a", True, "local"),
            ToolStatus("b", True, "container", image="img"),
            ToolStatus("c", True, "container", image="img"),
            ToolStatus("d", False, "none"),
        ]
        assert summarize(statuses) == {"local": 1, "container": 2, "missing": 1}

    def test_empty_input(self):
        assert summarize([]) == {"local": 0, "container": 0, "missing": 0}


class TestUnavailableNames:
    def test_returns_only_unavailable(self):
        statuses = [
            ToolStatus("a", True, "local"),
            ToolStatus("b", False, "none"),
            ToolStatus("c", False, "none"),
        ]
        assert unavailable_names(statuses) == ["b", "c"]

    def test_empty_when_all_available(self):
        statuses = [ToolStatus("a", True, "local")]
        assert unavailable_names(statuses) == []
