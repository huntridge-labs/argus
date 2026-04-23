"""Tests for argus.containers — container image manifest and DB caching."""

from pathlib import Path

from argus.containers import (
    CACHE_MOUNTS,
    CUSTOM_IMAGES,
    OFFICIAL_IMAGES,
    _default_cache_root,
    get_cache_mount,
    get_image,
)


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
            # SBOM-only scanners refuse to build args without an sbom_path
            # because the SBOM is required for the invocation; pass a
            # placeholder so this protocol test still exercises them.
            cfg: dict | None = None
            if getattr(cls, "supports_sbom", False) and name in {"grype", "trivy"}:
                cfg = {
                    "sbom_path": "/host/sbom.json",
                    "sbom_mount_path": "/sbom/sbom.json",
                }
            args = scanner.container_args(cfg)
            assert isinstance(args, list), (
                f"{name}.container_args() should return list"
            )


class TestCacheMounts:
    """Tests for DB cache volume mount logic."""

    def test_cache_mounts_has_db_scanners(self):
        """Scanners with heavy DB downloads should have cache entries."""
        for scanner in ("trivy", "grype", "clamav", "semgrep"):
            assert scanner in CACHE_MOUNTS, f"{scanner} missing from CACHE_MOUNTS"

    def test_cache_mounts_values_are_absolute_paths(self):
        for scanner, path in CACHE_MOUNTS.items():
            assert path.startswith("/"), (
                f"{scanner} cache path must be absolute: {path}"
            )

    def test_get_cache_mount_known_scanner(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ARGUS_CACHE_DIR", str(tmp_path))
        result = get_cache_mount("trivy")
        assert result is not None
        host_dir, container_dir = result
        assert container_dir == "/root/.cache/trivy"
        assert host_dir == tmp_path / "trivy"
        assert host_dir.is_dir()

    def test_get_cache_mount_alias_resolution(self, tmp_path, monkeypatch):
        """trivy-iac should resolve to trivy's cache via _ALIASES."""
        monkeypatch.setenv("ARGUS_CACHE_DIR", str(tmp_path))
        result = get_cache_mount("trivy-iac")
        assert result is not None
        _, container_dir = result
        assert container_dir == "/root/.cache/trivy"

    def test_get_cache_mount_opengrep_alias(self, tmp_path, monkeypatch):
        """opengrep should resolve to semgrep's cache."""
        monkeypatch.setenv("ARGUS_CACHE_DIR", str(tmp_path))
        result = get_cache_mount("opengrep")
        assert result is not None
        _, container_dir = result
        assert container_dir == "/root/.semgrep"

    def test_get_cache_mount_unknown_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ARGUS_CACHE_DIR", str(tmp_path))
        assert get_cache_mount("gitleaks") is None
        assert get_cache_mount("nonexistent") is None

    def test_get_cache_mount_creates_host_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ARGUS_CACHE_DIR", str(tmp_path))
        result = get_cache_mount("clamav")
        assert result is not None
        host_dir, _ = result
        assert host_dir.is_dir()

    def test_default_cache_root_uses_env(self, monkeypatch):
        monkeypatch.setenv("ARGUS_CACHE_DIR", "/custom/cache")
        assert _default_cache_root() == Path("/custom/cache")

    def test_default_cache_root_uses_tmpdir(self, monkeypatch):
        monkeypatch.delenv("ARGUS_CACHE_DIR", raising=False)
        root = _default_cache_root()
        assert "argus-cache" in str(root)

    def test_no_cache_scanners_excluded(self):
        """Scanners without heavy DBs should NOT be in CACHE_MOUNTS."""
        for scanner in ("bandit", "supply-chain", "osv-scanner"):
            assert scanner not in CACHE_MOUNTS, (
                f"{scanner} should not have a cache mount"
            )
