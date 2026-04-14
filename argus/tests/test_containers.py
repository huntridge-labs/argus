"""Tests for argus.containers — container image manifest."""

from argus.containers import OFFICIAL_IMAGES, CUSTOM_IMAGES, get_image


class TestContainerManifest:
    """Test the container image registry."""

    def test_official_images_not_empty(self):
        assert len(OFFICIAL_IMAGES) > 0

    def test_all_official_images_have_tags(self):
        for name, image in OFFICIAL_IMAGES.items():
            assert ":" in image, f"{name} image missing tag: {image}"

    def test_custom_images_not_empty(self):
        assert len(CUSTOM_IMAGES) > 0

    def test_get_image_official(self):
        assert get_image("trivy") == OFFICIAL_IMAGES["trivy"]

    def test_get_image_custom(self):
        assert get_image("bandit") == CUSTOM_IMAGES["bandit"]

    def test_get_image_unknown_returns_empty(self):
        assert get_image("nonexistent") == ""

    def test_known_official_scanners(self):
        expected = ["trivy", "grype", "syft", "gitleaks", "clamav",
                    "checkov", "osv-scanner", "zap"]
        for name in expected:
            assert name in OFFICIAL_IMAGES, f"Missing official image: {name}"

    def test_known_custom_scanners(self):
        expected = ["bandit", "semgrep", "supply-chain", "cli"]
        for name in expected:
            assert name in CUSTOM_IMAGES, f"Missing custom image: {name}"


class TestScannerContainerImages:
    """Verify all security scanner modules have container_image set.

    Linters (lint-*) are lightweight pip/npm tools and do not require
    container support, so they are excluded from these checks.
    """

    def _security_scanners(self):
        """Return only non-linter scanner entries."""
        from argus.scanners import SCANNER_REGISTRY
        return {
            name: cls
            for name, cls in SCANNER_REGISTRY.items()
            if not name.startswith("lint-")
        }

    def test_all_scanners_have_container_image(self):
        for name, cls in self._security_scanners().items():
            scanner = cls()
            assert hasattr(scanner, "container_image"), (
                f"{name} missing container_image"
            )

    def test_all_scanners_have_container_args(self):
        for name, cls in self._security_scanners().items():
            scanner = cls()
            assert hasattr(scanner, "container_args"), (
                f"{name} missing container_args method"
            )
            args = scanner.container_args()
            assert isinstance(args, list), (
                f"{name}.container_args() should return list"
            )
