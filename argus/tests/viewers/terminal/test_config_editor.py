"""Unit tests for argus.viewers.terminal.config_editor (Phase 2).

UI-free: no Textual. Pins comment-/format-preserving targeted edits,
the editable-row model, toggle/enum cycling, and validation.
"""

from __future__ import annotations

from argus.viewers.terminal.config_editor import (
    EditRow,
    apply_row,
    editable_rows,
    set_value,
    validate,
)


SAMPLE = """\
version: "1.0"
scanners:
  bandit:
    enabled: true
  gitleaks:
    enabled: false
reporting:
  severity_threshold: high  # fail gate
  output_dir: "./argus-results"
execution:
  backend: auto
  pull_policy: if-not-present
view:
  cve_source: nvd
  open_location: ask
"""


class TestEditableRows:
    def test_scanner_toggles_and_scalars(self):
        rows = {r.key: r for r in editable_rows(SAMPLE)}
        assert rows["scanner:bandit"].value == "on"
        assert rows["scanner:gitleaks"].value == "off"
        assert rows["reporting.severity_threshold"].value == "high"
        assert rows["execution.backend"].value == "auto"
        assert rows["execution.pull_policy"].value == "if-not-present"
        assert rows["view.cve_source"].value == "nvd"
        assert rows["view.open_location"].value == "ask"

    def test_enum_rows_carry_options(self):
        rows = {r.key: r for r in editable_rows(SAMPLE)}
        assert rows["view.cve_source"].kind == "enum"
        assert "github" in rows["view.cve_source"].options

    def test_absent_settings_not_offered(self):
        rows = {r.key: r for r in editable_rows("scanners:\n  bandit:\n    enabled: true\n")}
        assert "reporting.severity_threshold" not in rows
        assert "scanner:bandit" in rows

    def test_scanner_without_enabled_skipped(self):
        rows = {r.key: r for r in editable_rows("scanners:\n  bandit:\n    path: src\n")}
        assert "scanner:bandit" not in rows

    def test_malformed_yaml_returns_empty(self):
        assert editable_rows("{not: valid: yaml:") == []

    def test_non_mapping_returns_empty(self):
        assert editable_rows("- a\n- b\n") == []


class TestSetValue:
    def test_toggle_nested_scanner_enabled(self):
        out = set_value(SAMPLE, ["scanners", "bandit", "enabled"], "false")
        assert "  bandit:\n    enabled: false\n" in out
        # gitleaks untouched
        assert "  gitleaks:\n    enabled: false\n" in out

    def test_only_targeted_scanner_changes(self):
        out = set_value(SAMPLE, ["scanners", "gitleaks", "enabled"], "true")
        assert "  bandit:\n    enabled: true\n" in out      # bandit unchanged
        assert "  gitleaks:\n    enabled: true\n" in out

    def test_section_scalar_preserves_inline_comment(self):
        out = set_value(SAMPLE, ["reporting", "severity_threshold"], "medium")
        assert "severity_threshold: medium  # fail gate" in out

    def test_enum_scalar_edit(self):
        out = set_value(SAMPLE, ["execution", "backend"], "docker")
        assert "  backend: docker\n" in out

    def test_path_not_found_returns_none(self):
        assert set_value(SAMPLE, ["scanners", "nope", "enabled"], "true") is None
        assert set_value(SAMPLE, ["reporting", "nope"], "x") is None

    def test_no_op_returns_none(self):
        assert set_value(SAMPLE, ["execution", "backend"], "auto") is None

    def test_indentation_preserved(self):
        out = set_value(SAMPLE, ["view", "cve_source"], "github")
        assert "  cve_source: github\n" in out

    def test_list_items_not_matched(self):
        text = "formats:\n  - sarif\n  - json\nview:\n  cve_source: nvd\n"
        # ensure the list under formats doesn't confuse path tracking
        out = set_value(text, ["view", "cve_source"], "mitre")
        assert "  cve_source: mitre\n" in out


class TestRowCycling:
    def test_toggle_next_value(self):
        on = EditRow("scanner:x", "x", "toggle", "on", ["scanners", "x", "enabled"])
        off = EditRow("scanner:y", "y", "toggle", "off", ["scanners", "y", "enabled"])
        assert on.next_value() == "false"
        assert off.next_value() == "true"

    def test_enum_cycles_and_wraps(self):
        opts = ["nvd", "cve_org", "github", "mitre"]
        r = EditRow("view.cve_source", "cve", "enum", "mitre", ["view", "cve_source"], opts)
        assert r.next_value() == "nvd"  # wraps
        r2 = EditRow("view.cve_source", "cve", "enum", "nvd", ["view", "cve_source"], opts)
        assert r2.next_value() == "cve_org"

    def test_apply_row_returns_new_text_and_value(self):
        rows = {r.key: r for r in editable_rows(SAMPLE)}
        new_text, new_value = apply_row(SAMPLE, rows["scanner:bandit"])
        assert new_value == "false"
        assert "    enabled: false\n" in new_text

    def test_apply_row_noop_returns_none(self):
        # A row whose path vanished → no-op.
        ghost = EditRow("x", "x", "toggle", "on", ["scanners", "ghost", "enabled"])
        assert apply_row(SAMPLE, ghost) is None


class TestValidate:
    def test_valid_config_ok(self):
        assert validate(SAMPLE) is None

    def test_broken_yaml_reports(self):
        msg = validate("{not: valid: yaml:")
        assert msg and "Invalid YAML" in msg

    def test_non_mapping_reports(self):
        assert validate("- a\n- b\n") is not None

    def test_edited_config_still_valid(self):
        out = set_value(SAMPLE, ["scanners", "bandit", "enabled"], "false")
        assert validate(out) is None
