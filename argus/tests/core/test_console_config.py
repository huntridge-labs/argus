"""Unit tests for argus.core.console_config — Console user preferences.

UI-free: no Textual needed. Pins the persistence round-trip, the
defaults-on-garbage contract, and the motion/accessibility logic.
"""

from __future__ import annotations

import yaml

from argus.core.console_config import (
    ACCENTS,
    DEFAULT_ACCENT,
    DEFAULT_THEME,
    THEMES,
    ConsoleSettings,
    load_settings,
    save_settings,
    settings_path,
)


class TestDefaultsAndNormalization:
    def test_defaults_are_valid(self):
        s = ConsoleSettings()
        assert s.theme in THEMES
        assert s.accent in ACCENTS
        assert s.animations is True
        assert s.notifications is True

    def test_unknown_theme_and_accent_snap_to_default(self):
        s = ConsoleSettings(theme="not-a-theme", accent="chartreuse").normalized()
        assert s.theme == DEFAULT_THEME
        assert s.accent == DEFAULT_ACCENT

    def test_from_dict_ignores_unknown_keys(self):
        s = ConsoleSettings.from_dict({"theme": "nord", "bogus": 123})
        assert s.theme == "nord"
        assert not hasattr(s, "bogus")

    def test_from_dict_on_non_mapping_returns_defaults(self):
        assert ConsoleSettings.from_dict(None) == ConsoleSettings()
        assert ConsoleSettings.from_dict([1, 2]) == ConsoleSettings()


class TestMotionLogic:
    def test_reduced_motion_overrides_animations(self):
        s = ConsoleSettings(animations=True, reduced_motion=True)
        assert s.motion_enabled is False

    def test_animations_on_and_no_reduced_motion_plays(self):
        s = ConsoleSettings(animations=True, reduced_motion=False)
        assert s.motion_enabled is True

    def test_env_kill_switch_forces_still(self, monkeypatch):
        monkeypatch.setenv("ARGUS_NO_ANIMATION", "1")
        s = ConsoleSettings(animations=True, reduced_motion=False)
        assert s.motion_enabled is False


class TestPersistence:
    def test_round_trip(self, tmp_path):
        path = tmp_path / "console.yml"
        original = ConsoleSettings(theme="dracula", accent="magenta",
                                   animations=False, notifications=False)
        save_settings(original, path)
        loaded = load_settings(path)
        assert loaded == original.normalized()

    def test_save_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "nested" / "deeper" / "console.yml"
        save_settings(ConsoleSettings(), path)
        assert path.is_file()

    def test_load_missing_file_returns_defaults(self, tmp_path):
        assert load_settings(tmp_path / "nope.yml") == ConsoleSettings()

    def test_load_malformed_yaml_returns_defaults(self, tmp_path):
        path = tmp_path / "console.yml"
        path.write_text("{not: valid: yaml:", encoding="utf-8")
        assert load_settings(path) == ConsoleSettings()

    def test_load_non_mapping_returns_defaults(self, tmp_path):
        path = tmp_path / "console.yml"
        path.write_text("- a\n- b\n", encoding="utf-8")
        assert load_settings(path) == ConsoleSettings()

    def test_saved_file_is_human_readable_yaml(self, tmp_path):
        path = tmp_path / "console.yml"
        save_settings(ConsoleSettings(theme="nord"), path)
        data = yaml.safe_load(path.read_text())
        assert data["theme"] == "nord"
        assert set(data) == {
            "theme", "accent", "animations", "reduced_motion", "notifications",
        }

    def test_invalid_saved_value_is_normalized_on_write(self, tmp_path):
        path = tmp_path / "console.yml"
        save_settings(ConsoleSettings(theme="bogus"), path)
        assert yaml.safe_load(path.read_text())["theme"] == DEFAULT_THEME


class TestAdvanceAndRows:
    def test_advance_theme_cycles_and_wraps(self):
        s = ConsoleSettings(theme=THEMES[-1])
        assert s.advance("theme").theme == THEMES[0]

    def test_advance_accent_cycles(self):
        s = ConsoleSettings(accent=ACCENTS[0])
        assert s.advance("accent").accent == ACCENTS[1]

    def test_advance_toggle_flips_bool(self):
        s = ConsoleSettings(animations=True)
        assert s.advance("animations").animations is False
        assert s.advance("animations").advance("animations").animations is True

    def test_advance_unknown_key_is_noop(self):
        s = ConsoleSettings()
        assert s.advance("not-a-setting") == s

    def test_advance_returns_new_instance(self):
        s = ConsoleSettings(animations=True)
        advanced = s.advance("animations")
        assert s.animations is True  # original untouched (immutable update)
        assert advanced is not s

    def test_with_value_sets_specific_theme(self):
        s = ConsoleSettings(theme=DEFAULT_THEME)
        assert s.with_value("theme", "nord").theme == "nord"

    def test_with_value_invalid_snaps_to_default(self):
        s = ConsoleSettings()
        assert s.with_value("theme", "not-a-theme").theme == DEFAULT_THEME

    def test_with_value_unknown_key_is_noop(self):
        s = ConsoleSettings()
        assert s.with_value("not-a-setting", "x") == s

    def test_with_value_returns_new_instance(self):
        s = ConsoleSettings(theme=DEFAULT_THEME)
        out = s.with_value("theme", "dracula")
        assert s.theme == DEFAULT_THEME  # original untouched
        assert out is not s and out.theme == "dracula"

    def test_display_rows_cover_all_settings(self):
        rows = ConsoleSettings(theme="nord", animations=False).display_rows()
        by_key = {key: (label, text) for key, label, text in rows}
        assert by_key["theme"][1] == "nord"
        assert by_key["animations"][1] == "off"
        # Every persisted field has a row.
        assert set(by_key) == {
            "theme", "accent", "animations", "reduced_motion", "notifications",
        }

    def test_to_dict_has_only_persisted_fields(self):
        # Guard against settings-screen metadata leaking into the saved file.
        assert set(ConsoleSettings().to_dict()) == {
            "theme", "accent", "animations", "reduced_motion", "notifications",
        }


class TestSettingsPath:
    def test_respects_xdg_config_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        assert settings_path() == tmp_path / "argus" / "console.yml"

    def test_falls_back_to_home_config(self, monkeypatch):
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        p = settings_path()
        assert p.name == "console.yml"
        assert p.parent.name == "argus"
