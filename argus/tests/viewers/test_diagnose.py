"""Tests for argus.viewers.diagnose — missing-results-JSON remediation hints.

Three branches matter:
- argus.yml exists and `reporting.formats` omits `json` → targeted hint
  identifying the config root cause.
- argus.yml exists and lists `json` → fall back to the generic hint
  (config isn't the cause).
- no argus.yml found anywhere up the tree → generic hint.

Plus defensive paths: malformed YAML, missing reporting key, etc., all
fall back to the generic hint without raising.
"""

from __future__ import annotations

from pathlib import Path

from argus.viewers.diagnose import (
    _find_nearby_argus_config,
    _read_reporting_formats,
    diagnose_missing_results,
)


# ───────────────────────────────────────────────
# diagnose_missing_results — public surface
# ───────────────────────────────────────────────


class TestDiagnoseMissingResults:
    def test_targeted_hint_when_config_omits_json(self, tmp_path, monkeypatch):
        """argus.yml present, json NOT in reporting.formats → message names
        the file, the actual formats value, and offers a one-shot CLI fix
        plus the config-edit fix."""
        config = tmp_path / "argus.yml"
        config.write_text(
            "reporting:\n  formats:\n    - terminal\n    - sarif\n"
        )
        monkeypatch.chdir(tmp_path)

        msg = diagnose_missing_results(tmp_path / "argus-results.json")

        # Required: identifies the file.
        assert "argus-results.json" in msg
        # Required: message names config root cause.
        assert "argus.yml" in msg
        assert "reporting.formats" in msg
        assert "'terminal'" in msg and "'sarif'" in msg
        # Required: at least one config fix and one CLI fix.
        assert "Add 'json' to reporting.formats" in msg
        assert "argus scan --format json" in msg
        # Required: retry instruction echoes the searched path.
        assert "argus view" in msg

    def test_generic_hint_when_no_argus_yml(self, tmp_path, monkeypatch):
        """No argus.yml anywhere up the tree → generic hint, no false claim
        about config being the cause."""
        # Use an isolated tmp dir as cwd; walk-up shouldn't find any
        # config because tmp dirs are well outside the repo root.
        sub = tmp_path / "isolated"
        sub.mkdir()
        monkeypatch.chdir(sub)

        msg = diagnose_missing_results(sub / "argus-results.json")

        # Still identifies the file + still gives both fix paths.
        assert "argus-results.json" in msg
        assert "Add 'json' to reporting.formats in argus.yml" in msg
        assert "argus scan --format json" in msg
        # Doesn't make a confident claim about a config we never found.
        assert "Detected" not in msg

    def test_generic_hint_when_config_includes_json(self, tmp_path, monkeypatch):
        """Config has json — bug is somewhere else (wrong path, scan never
        ran, output dir mismatch). Don't blame the config."""
        config = tmp_path / "argus.yml"
        config.write_text(
            "reporting:\n  formats:\n    - terminal\n    - json\n"
        )
        monkeypatch.chdir(tmp_path)

        msg = diagnose_missing_results(tmp_path / "argus-results.json")

        # Generic hint path — not the targeted one.
        assert "Detected" not in msg
        # Both fixes still listed (user might still need to run the scan).
        assert "argus scan --format json" in msg

    def test_unparseable_argus_yml_falls_back_to_generic(self, tmp_path, monkeypatch):
        """Broken YAML must NOT mask the original missing-file diagnostic
        with a parse-error traceback. Falls back to the generic hint."""
        config = tmp_path / "argus.yml"
        config.write_text("reporting:\n  formats: [terminal,, : :")
        monkeypatch.chdir(tmp_path)

        msg = diagnose_missing_results(tmp_path / "argus-results.json")

        # No traceback / exception leakage.
        assert "Traceback" not in msg
        assert "yaml" not in msg.lower()
        # Falls back to generic path.
        assert "Detected" not in msg
        assert "argus-results.json" in msg

    def test_argus_yml_without_reporting_key_falls_back(self, tmp_path, monkeypatch):
        """Config exists but doesn't define reporting.formats → can't make
        a confident 'json missing from formats' claim, generic hint fires."""
        config = tmp_path / "argus.yml"
        config.write_text("scanners:\n  bandit:\n    enabled: true\n")
        monkeypatch.chdir(tmp_path)

        msg = diagnose_missing_results(tmp_path / "argus-results.json")
        assert "Detected" not in msg

    def test_retry_arg_uses_parent_for_results_filename(self, tmp_path, monkeypatch):
        """When the searched path ends in argus-results.json, the retry
        hint should point at its parent dir (what argus view actually
        accepts), not the JSON file itself."""
        config = tmp_path / "argus.yml"
        config.write_text("reporting:\n  formats: [terminal]\n")
        monkeypatch.chdir(tmp_path)

        run_dir = tmp_path / "argus-results" / "2026-05-05T10-00-00Z"
        msg = diagnose_missing_results(run_dir / "argus-results.json")

        assert f"argus view {run_dir}" in msg

    def test_retry_arg_falls_back_to_placeholder_for_empty_path(self, tmp_path, monkeypatch):
        """A relative '.' or empty path renders as a literal placeholder
        rather than a useless 'argus view .' line."""
        monkeypatch.chdir(tmp_path)
        msg = diagnose_missing_results(Path("."))
        assert "argus view <results-dir>" in msg


# ───────────────────────────────────────────────
# Helpers exercised separately for confidence at boundaries
# ───────────────────────────────────────────────


class TestFindNearbyArgusConfig:
    def test_finds_in_starting_dir(self, tmp_path):
        config = tmp_path / "argus.yml"
        config.write_text("# empty\n")
        assert _find_nearby_argus_config(tmp_path) == config

    def test_walks_up_to_find_config(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        config = tmp_path / "argus.yml"
        config.write_text("# empty\n")
        assert _find_nearby_argus_config(nested) == config

    def test_returns_none_when_no_config_in_tree(self, tmp_path):
        # tmp_path's tree is well-isolated from any repo with argus.yml.
        assert _find_nearby_argus_config(tmp_path) is None

    def test_recognises_alternate_config_names(self, tmp_path):
        # argus.yaml and the dotted variants are all valid filenames.
        for name in ("argus.yaml", ".argus.yml", ".argus.yaml"):
            sub = tmp_path / name.replace(".", "_")
            sub.mkdir()
            config = sub / name
            config.write_text("# empty\n")
            assert _find_nearby_argus_config(sub) == config


class TestReadReportingFormats:
    def test_reads_formats_list(self, tmp_path):
        config = tmp_path / "argus.yml"
        config.write_text(
            "reporting:\n  formats:\n    - terminal\n    - json\n"
        )
        assert _read_reporting_formats(config) == ["terminal", "json"]

    def test_returns_none_for_missing_reporting_key(self, tmp_path):
        config = tmp_path / "argus.yml"
        config.write_text("scanners:\n  bandit:\n    enabled: true\n")
        assert _read_reporting_formats(config) is None

    def test_returns_none_for_unparseable_yaml(self, tmp_path):
        config = tmp_path / "argus.yml"
        config.write_text("reporting: [{")
        assert _read_reporting_formats(config) is None

    def test_returns_none_when_formats_isnt_a_list(self, tmp_path):
        config = tmp_path / "argus.yml"
        config.write_text("reporting:\n  formats: terminal\n")
        assert _read_reporting_formats(config) is None
