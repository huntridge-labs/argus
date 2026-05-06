"""Tests for validate_config's ``containers:`` block validation.

Locks in the contract: typo'd image-entry keys, missing image/dockerfile
fields, empty images list, and invalid sub-scanner names all surface
during ``argus validate`` instead of failing silently at scan time.
"""

import pytest

from argus.core.schema import validate_config


def _errors(data: dict) -> list:
    """Run validation and return only fatal errors (drops warnings)."""
    return [e for e in validate_config(data) if e.level == "error"]


def _warnings(data: dict) -> list:
    return [e for e in validate_config(data) if e.level == "warning"]


def _has_error_at(errors, path_substr: str, msg_substr: str = "") -> bool:
    return any(
        path_substr in e.path and msg_substr in e.message
        for e in errors
    )


# --------------------------------------------------------------------- #
# Happy paths                                                           #
# --------------------------------------------------------------------- #


class TestContainersValid:
    def test_minimal_image_entry(self):
        cfg = {"containers": {"images": [{"image": "nginx:latest"}]}}
        assert _errors(cfg) == []

    def test_dockerfile_entry(self):
        cfg = {
            "containers": {
                "images": [
                    {
                        "image": "myapp:dev",
                        "dockerfile": "docker/Dockerfile",
                        "context": ".",
                    }
                ]
            }
        }
        assert _errors(cfg) == []

    def test_discover_only(self):
        cfg = {"containers": {"discover": True, "search_paths": ["docker/"]}}
        assert _errors(cfg) == []

    def test_scanners_subset(self):
        cfg = {
            "containers": {
                "images": [{"image": "x:1"}],
                "scanners": ["trivy", "grype"],
            }
        }
        assert _errors(cfg) == []


# --------------------------------------------------------------------- #
# Structural errors                                                     #
# --------------------------------------------------------------------- #


class TestContainersStructuralErrors:
    def test_not_a_mapping(self):
        cfg = {"containers": ["nginx:latest"]}
        errors = _errors(cfg)
        assert _has_error_at(errors, "containers", "Must be a mapping")

    def test_no_targets_at_all(self):
        # No images, no discover — nothing for ``argus scan container`` to do.
        cfg = {"containers": {}}
        errors = _errors(cfg)
        assert _has_error_at(errors, "containers", "at least one")

    def test_empty_images_list_is_warning(self):
        cfg = {"containers": {"images": [], "discover": True}}
        warnings = _warnings(cfg)
        assert any("images" in w.path and "Empty" in w.message for w in warnings)

    def test_images_must_be_list(self):
        cfg = {"containers": {"images": {"image": "x:1"}}}
        errors = _errors(cfg)
        assert _has_error_at(errors, "containers.images", "Must be a list")


# --------------------------------------------------------------------- #
# Image-entry validation                                                #
# --------------------------------------------------------------------- #


class TestImageEntryErrors:
    def test_image_entry_missing_image_and_dockerfile(self):
        cfg = {"containers": {"images": [{"context": "."}]}}
        errors = _errors(cfg)
        assert _has_error_at(errors, "containers.images[0]", "must have either")
        assert _has_error_at(errors, "containers.images[0]", "dockerfile")

    def test_unknown_image_entry_key_is_warning(self):
        cfg = {
            "containers": {
                "images": [
                    {"image": "x:1", "registry_url": "ghcr.io"}  # not a real key
                ]
            }
        }
        warnings = _warnings(cfg)
        assert any("registry_url" in w.path for w in warnings)

    def test_image_field_must_be_string(self):
        cfg = {"containers": {"images": [{"image": 42}]}}
        errors = _errors(cfg)
        assert _has_error_at(errors, "containers.images[0].image", "Must be a string")

    def test_image_entry_must_be_mapping(self):
        cfg = {"containers": {"images": ["nginx:latest"]}}  # bare string, not dict
        errors = _errors(cfg)
        assert _has_error_at(
            errors, "containers.images[0]", "Must be a mapping",
        )


# --------------------------------------------------------------------- #
# Sub-scanner whitelist                                                 #
# --------------------------------------------------------------------- #


class TestSubScannerValidation:
    def test_invalid_subscanner_name(self):
        cfg = {
            "containers": {
                "images": [{"image": "x:1"}],
                "scanners": ["trivy", "snyk"],  # snyk isn't supported
            }
        }
        errors = _errors(cfg)
        assert _has_error_at(errors, "containers.scanners[1]", "Unknown")

    def test_scanners_must_be_list(self):
        cfg = {
            "containers": {
                "images": [{"image": "x:1"}],
                "scanners": "trivy,grype",  # comma-string, not a YAML list
            }
        }
        errors = _errors(cfg)
        assert _has_error_at(errors, "containers.scanners", "Must be a list")


# --------------------------------------------------------------------- #
# Unknown top-level containers key                                      #
# --------------------------------------------------------------------- #


class TestUnknownKeys:
    def test_unknown_top_level_key_is_warning(self):
        cfg = {
            "containers": {
                "images": [{"image": "x:1"}],
                "matrix": {"strategy": "fail-fast"},  # not a real key
            }
        }
        warnings = _warnings(cfg)
        assert any("matrix" in w.path for w in warnings)
