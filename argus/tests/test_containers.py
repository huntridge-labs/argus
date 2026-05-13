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


class TestOfficialImagesDigestPinned:
    """Every third-party image in OFFICIAL_IMAGES must carry a
    ``@sha256:...`` digest pin alongside its tag. The pin is what makes
    the image content-addressable — Docker enforces the content-hash
    match at pull time, which paired with argus.core.image_verify
    routes third-party images through the ``VERIFIED_DIGEST_PIN``
    path instead of the warn-only ``SKIPPED_TAG_PIN`` path.

    Surfaced by the post-PR-146 supply-chain audit; guarding it here
    so a future Renovate-driven update that loses the digest segment
    (or a manual edit that strips it) fails the test rather than
    silently demoting all third-party images back to tag-only trust.
    """

    def test_every_official_image_has_digest(self):
        import re
        digest_re = re.compile(r"@sha256:[a-f0-9]{64}$")
        for name, image in OFFICIAL_IMAGES.items():
            assert digest_re.search(image), (
                f"{name} image lacks @sha256: digest pin: {image}"
            )

    def test_digest_pin_classified_by_image_verify(self):
        from argus.core.image_verify import has_digest_pin
        for name, image in OFFICIAL_IMAGES.items():
            assert has_digest_pin(image), (
                f"{name} not recognised by image_verify.has_digest_pin: "
                f"{image}"
            )

    def test_expected_version_strips_digest_suffix(self):
        """The tool-version comparator must extract the version segment
        without the digest tail. Without this, every container_runtime
        version check would compare against ``sha256`` and fail."""
        from argus.containers import expected_version
        assert expected_version(
            "aquasec/trivy:0.70.0@sha256:" + "a" * 64,
        ) == "0.70.0"
        assert expected_version(
            "anchore/grype:v0.112.0@sha256:" + "b" * 64,
        ) == "0.112.0"  # leading ``v`` stripped

    def test_expected_version_works_on_each_official_image(self):
        """End-to-end: every OFFICIAL_IMAGES entry yields a parseable
        version string (not ``sha256``, not an empty tail)."""
        from argus.containers import expected_version, OFFICIAL_IMAGES as imgs
        for name, image in imgs.items():
            v = expected_version(image)
            assert v is not None and v, f"{name}: no version parsed from {image}"
            assert v != "sha256", (
                f"{name}: expected_version returned digest tail "
                f"(parser missed the @ split): {image}"
            )


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
        """Scanners must expose container CLI args via build_args or container_args."""
        from argus.core.scanner_template import ScanPaths

        for name, cls in self._security_scanners().items():
            scanner = cls()
            has_build_args = hasattr(scanner, "build_args")
            has_container_args = hasattr(scanner, "container_args")
            assert has_build_args or has_container_args, (
                f"{name} missing both build_args and container_args"
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

            if has_build_args:
                paths = ScanPaths(workspace="/workspace", output="/output/results.json")
                args = scanner.build_args(paths, cfg or {})
            else:
                args = scanner.container_args(cfg)
            assert isinstance(args, list), (
                f"{name} container args method should return list"
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
