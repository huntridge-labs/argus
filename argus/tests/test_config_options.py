"""Tests for the machine-readable config surface (argus.core.config_options)."""

from __future__ import annotations

import argus
from argus.core.config_options import (
    BASE_OPTIONS,
    ConfigOption,
    NativeIgnore,
    config_surface,
    scanner_config_options,
    scanner_native_ignore,
)
from argus.scanners import SCANNER_REGISTRY

_BASE_KEYS = {"enabled", "path", "severity_threshold", "config_file", "exclude"}


def test_surface_is_versioned_and_complete() -> None:
    s = config_surface()
    assert s["argus_version"] == argus.__version__
    assert s["config_version"] == "1.0"
    assert "critical" in s["severity_levels"]
    # Every registered scanner is present exactly once.
    names = [x["name"] for x in s["scanners"]]
    assert set(names) == set(SCANNER_REGISTRY)
    assert len(names) == len(set(names)) == len(SCANNER_REGISTRY)


def test_schema_is_embedded_from_the_installed_package() -> None:
    schema = config_surface()["schema"]
    assert isinstance(schema, dict)
    assert "properties" in schema and "scanners" in schema["properties"]


def test_every_scanner_carries_the_base_options() -> None:
    for entry in config_surface()["scanners"]:
        keys = {o["key"] for o in entry["options"]}
        assert _BASE_KEYS <= keys, f"{entry['name']} missing base options"


def test_checkov_exposes_skip_check_as_an_ignore_knob() -> None:
    checkov = next(x for x in config_surface()["scanners"] if x["name"] == "checkov")
    skip = next(o for o in checkov["options"] if o["key"] == "skip_check")
    assert skip["kind"] == "rule_ids" and skip["ignore"] is True
    assert "skip_check" in checkov["ignore_keys"]


def test_container_and_zap_ignore_knobs() -> None:
    surface = {x["name"]: x for x in config_surface()["scanners"]}
    assert "expose_ignore_ports" in surface["container"]["ignore_keys"]
    assert "services_ignore" in surface["container"]["ignore_keys"]
    assert "rules_file" in surface["zap"]["ignore_keys"]


def test_native_ignore_for_scanners_without_a_direct_knob() -> None:
    surface = {x["name"]: x for x in config_surface()["scanners"]}
    assert surface["trivy"]["native_ignore"]["file"] == ".trivyignore"
    assert surface["gitleaks"]["native_ignore"]["comment"] == "#gitleaks:allow"


def test_class_declared_options_win_over_central_and_base() -> None:
    # A scanner may own its metadata; its declaration dedupes ahead of the base.
    class FakeScanner:
        name = "fake"
        config_options = (ConfigOption("enabled", "On?", "bool", "custom"),)
        native_ignore = NativeIgnore(comment="# fake:skip")

    opts = scanner_config_options("fake", FakeScanner)
    enabled = [o for o in opts if o.key == "enabled"]
    assert len(enabled) == 1 and enabled[0].help == "custom"
    # Base keys still present.
    assert _BASE_KEYS <= {o.key for o in opts}
    assert scanner_native_ignore("fake", FakeScanner).comment == "# fake:skip"


def test_curated_metadata_never_orphans() -> None:
    """Every curated extras/native-ignore key must name a REGISTERED scanner.

    Guards the scale seam: if a scanner is renamed or removed, its curated
    metadata would otherwise silently orphan (the scanner would fall back to
    base-only knobs and the stale entry would linger forever)."""
    from argus.core.config_options import _NATIVE_IGNORE, _SCANNER_EXTRAS

    registered = set(SCANNER_REGISTRY)
    assert set(_SCANNER_EXTRAS) <= registered, (
        f"orphaned _SCANNER_EXTRAS keys: {set(_SCANNER_EXTRAS) - registered}"
    )
    assert set(_NATIVE_IGNORE) <= registered, (
        f"orphaned _NATIVE_IGNORE keys: {set(_NATIVE_IGNORE) - registered}"
    )


def test_config_option_to_dict_omits_empty_but_keeps_core() -> None:
    d = ConfigOption("k", "L").to_dict()
    assert d["key"] == "k" and d["label"] == "L" and d["kind"] == "string"
    assert "ignore" not in d  # False is omitted
    assert "example" not in d  # None is omitted
    assert BASE_OPTIONS[0].key == "enabled"
