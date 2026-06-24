"""Tests for installed-add-on discovery + its surfacing in version/provenance."""

from __future__ import annotations

from importlib import metadata

from argus.core import addons
from argus.core.models import ScanSummary


class _FakeDist:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeEP:
    def __init__(self, dist_name: str) -> None:
        self.dist = _FakeDist(dist_name)


def _fake_entry_points(mapping: dict[str, list[_FakeEP]]):
    def _entry_points(group: str):
        return mapping.get(group, [])

    return _entry_points


class TestInstalledAddons:
    def test_groups_dedup_and_excludes_core(self, monkeypatch):
        mapping = {
            "argus.cli_commands": [_FakeEP("argus-enterprise"), _FakeEP("argus-security")],
            "argus.console_providers": [_FakeEP("argus-enterprise")],
            "argus.viewers.browser_plugins": [_FakeEP("argus-enterprise")],
            # core registers its built-in reporters here — and as argus_security
            # (underscore) to prove PEP 503 normalization excludes it too.
            "argus.reporters": [_FakeEP("argus_security")],
        }
        monkeypatch.setattr(addons.metadata, "entry_points", _fake_entry_points(mapping))
        monkeypatch.setattr(addons.metadata, "version", lambda name: "0.3.0")

        result = addons.installed_addons()
        assert result == [
            {
                "name": "argus-enterprise",
                "version": "0.3.0",
                "groups": [
                    "argus.cli_commands",
                    "argus.console_providers",
                    "argus.viewers.browser_plugins",
                ],
            }
        ]

    def test_empty_when_only_core(self, monkeypatch):
        monkeypatch.setattr(
            addons.metadata,
            "entry_points",
            _fake_entry_points({"argus.reporters": [_FakeEP("argus-security")]}),
        )
        assert addons.installed_addons() == []

    def test_unknown_version_when_dist_missing(self, monkeypatch):
        monkeypatch.setattr(
            addons.metadata,
            "entry_points",
            _fake_entry_points({"argus.reporters": [_FakeEP("ghost-addon")]}),
        )

        def _missing(name):
            raise metadata.PackageNotFoundError(name)

        monkeypatch.setattr(addons.metadata, "version", _missing)
        assert addons.installed_addons() == [
            {"name": "ghost-addon", "version": "unknown", "groups": ["argus.reporters"]}
        ]

    def test_never_raises(self, monkeypatch):
        def _boom(group):
            raise RuntimeError("metadata is unhappy")

        monkeypatch.setattr(addons.metadata, "entry_points", _boom)
        assert addons.installed_addons() == []


class TestScanSummaryProvenance:
    def test_round_trips_addons(self):
        inventory = [
            {"name": "argus-enterprise", "version": "0.3.0", "groups": ["argus.cli_commands"]}
        ]
        summary = ScanSummary(results=[], addons=inventory)
        data = summary.to_dict()
        assert data["addons"] == inventory
        assert ScanSummary.from_dict(data).addons == inventory

    def test_addons_omitted_when_none(self):
        assert "addons" not in ScanSummary(results=[]).to_dict()


class TestVersionString:
    def test_lists_addons(self, monkeypatch):
        from argus import cli

        monkeypatch.setattr(
            addons,
            "installed_addons",
            lambda: [{"name": "argus-enterprise", "version": "0.3.0", "groups": []}],
        )
        out = cli._get_version()
        assert "Installed add-ons:" in out
        assert "argus-enterprise 0.3.0" in out

    def test_core_only_has_no_addon_section(self, monkeypatch):
        from argus import cli

        monkeypatch.setattr(addons, "installed_addons", lambda: [])
        out = cli._get_version()
        assert "Installed add-ons" not in out
        assert out.startswith("argus ")
