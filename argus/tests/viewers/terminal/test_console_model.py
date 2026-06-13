"""Unit tests for argus.viewers.terminal.console_model.

Textual-free (imports only run_discovery + findings_view), so these run
in CI without the [terminal] extra. They pin the home-screen status
summary, the menu shape, and the accent palette.
"""

from __future__ import annotations

import json

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.core.run_discovery import RESULTS_FILENAME
from argus.viewers.terminal import console_model as cm


def _write_run(dir_path, sevs):
    dir_path.mkdir(parents=True, exist_ok=True)
    findings = [
        Finding(id=f"CVE-{i}", severity=s, title="t", scanner="trivy")
        for i, s in enumerate(sevs)
    ]
    (dir_path / RESULTS_FILENAME).write_text(
        json.dumps(ScanSummary(results=[ScanResult(scanner="trivy", findings=findings)]).to_dict())
    )


class TestMenuAndBanner:
    def test_menu_keys_are_unique_and_expected(self):
        keys = [item.key for item in cm.MENU]
        assert keys == ["scan", "findings", "configure", "init", "settings", "docs", "quit"]
        assert len(keys) == len(set(keys))

    def test_every_menu_item_has_label_and_hint(self):
        for item in cm.MENU:
            assert item.label and item.hint and item.icon

    def test_banner_is_multiline(self):
        assert len(cm.ARGUS_BANNER.strip().splitlines()) >= 5


class TestAccent:
    def test_known_accent_maps_to_hex(self):
        assert cm.accent_hex("green") == cm.ACCENT_HEX["green"]

    def test_unknown_accent_defaults_to_brand_green(self):
        assert cm.accent_hex("chartreuse") == cm.ACCENT_HEX["green"]


class TestHomeStatus:
    def test_no_runs_no_config(self, tmp_path):
        status = cm.home_status(tmp_path)
        assert status["run_count"] == 0
        assert status["config_present"] is False
        line = cm.status_line(status)
        assert "no argus.yml" in line
        assert "no scan runs" in line

    def test_with_runs_and_config(self, tmp_path):
        _write_run(tmp_path / "run-1", [Severity.CRITICAL, Severity.LOW])
        cfg = tmp_path / "argus.yml"
        cfg.write_text("scanners: [bandit]\n")
        status = cm.home_status(tmp_path, config_path=cfg)
        assert status["run_count"] == 1
        assert status["latest_count"] == 2
        assert status["latest_severity"] == Severity.CRITICAL
        assert status["config_present"] is True
        line = cm.status_line(status)
        assert "argus.yml found" in line
        assert "run-1" in line

    def test_status_line_clean_run_has_no_severity_glyph_crash(self, tmp_path):
        _write_run(tmp_path / "clean", [])
        status = cm.home_status(tmp_path)
        # worst severity None → neutral glyph, no exception
        assert "none" in cm.status_line(status)
