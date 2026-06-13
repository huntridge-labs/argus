"""Persisted user preferences for the Argus Console (the interactive TUI).

UI-free on purpose: no Textual import, so the load/save/validation logic
is unit-testable without the ``[terminal]`` extra and the same settings
object can be read by any front-end. These are *user* preferences (how
the console looks and behaves for this person on this machine) — distinct
from ``argus.yml``, which is *project* scan configuration.

Persisted as YAML at ``$XDG_CONFIG_HOME/argus/console.yml`` (falling back
to ``~/.config/argus/console.yml``). YAML keeps us on the single runtime
dependency (``pyyaml``) the bare install already carries — no TOML writer
dependency needed.

Unknown keys in the file are ignored and invalid values fall back to the
default for that field, so a settings file written by a newer Argus (or
hand-edited badly) never crashes the console — it degrades to defaults
for whatever it can't understand.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, fields
from pathlib import Path

import yaml


# Curated theme list. These names match Textual's built-in registered
# themes plus the bespoke ``argus-dark`` we register at app start, so a
# saved value can be handed straight to ``App.theme``. Kept here (UI-free)
# as the single source of truth for "which themes may a user pick"; the
# Settings screen renders exactly this list.
THEMES: tuple[str, ...] = (
    "argus-dark",
    "textual-dark",
    "textual-light",
    "nord",
    "gruvbox",
    "catppuccin-mocha",
    "dracula",
    "tokyo-night",
    "monokai",
    "flexoki",
    "solarized-light",
)
DEFAULT_THEME = "argus-dark"

# Accent colours offered in Settings. Plain names so they render in any
# terminal and serialise cleanly; the app maps the choice onto the theme's
# accent token.
ACCENTS: tuple[str, ...] = (
    "green", "lime", "cyan", "blue", "magenta", "yellow", "orange", "purple",
)
DEFAULT_ACCENT = "green"


# Settings-screen rows: (field key, human label, kind). ``cycle`` fields
# step through a fixed option list; ``toggle`` fields flip a bool. Order is
# the on-screen order. Module-level (not a dataclass attr) so it never
# leaks into the serialized settings.
_SETTING_ROWS: tuple[tuple[str, str, str], ...] = (
    ("theme", "Theme", "cycle"),
    ("accent", "Accent colour", "cycle"),
    ("animations", "Animations", "toggle"),
    ("reduced_motion", "Reduced motion", "toggle"),
    ("notifications", "Notifications", "toggle"),
)


def _next_in_cycle(value: str, options: tuple[str, ...], default: str) -> str:
    """Return the option after ``value`` in ``options``, wrapping around.

    An unrecognized ``value`` starts the cycle from ``default``.
    """
    try:
        idx = options.index(value)
    except ValueError:
        return default
    return options[(idx + 1) % len(options)]


@dataclass
class ConsoleSettings:
    """How the Argus Console looks and behaves for this user.

    Every field has a safe default so a missing or partial settings file
    yields a fully usable console. ``reduced_motion`` is honoured even
    when ``animations`` is True — it's the stronger signal (it also tracks
    the conventional accessibility preference).
    """

    theme: str = DEFAULT_THEME
    accent: str = DEFAULT_ACCENT
    animations: bool = True
    reduced_motion: bool = False
    notifications: bool = True

    @property
    def motion_enabled(self) -> bool:
        """True only when animations should actually play.

        ``reduced_motion`` overrides ``animations`` — a user who asked for
        reduced motion gets none, regardless of the animations toggle.
        Also yields to the ``NO_COLOR``-adjacent ``ARGUS_NO_ANIMATION``
        escape hatch so CI / screenshot capture can force a still frame.
        """
        if os.environ.get("ARGUS_NO_ANIMATION"):
            return False
        return self.animations and not self.reduced_motion

    def normalized(self) -> "ConsoleSettings":
        """Return a copy with out-of-range values snapped back to defaults.

        Keeps the in-memory object trustworthy even if it was built from a
        hand-edited file: an unknown theme/accent falls back rather than
        being handed to Textual (which would raise on an unregistered
        theme name).
        """
        theme = self.theme if self.theme in THEMES else DEFAULT_THEME
        accent = self.accent if self.accent in ACCENTS else DEFAULT_ACCENT
        return ConsoleSettings(
            theme=theme,
            accent=accent,
            animations=bool(self.animations),
            reduced_motion=bool(self.reduced_motion),
            notifications=bool(self.notifications),
        )

    def advance(self, key: str) -> "ConsoleSettings":
        """Return a copy with setting ``key`` advanced one step.

        ``cycle`` settings (theme, accent) step to the next option and wrap;
        ``toggle`` settings flip. Unknown keys return an unchanged copy, so
        the Settings screen can call this on any row without guarding.
        """
        data = self.to_dict()
        if key == "theme":
            data["theme"] = _next_in_cycle(self.theme, THEMES, DEFAULT_THEME)
        elif key == "accent":
            data["accent"] = _next_in_cycle(self.accent, ACCENTS, DEFAULT_ACCENT)
        elif key in {"animations", "reduced_motion", "notifications"}:
            data[key] = not data[key]
        return ConsoleSettings.from_dict(data)

    def display_rows(self) -> list[tuple[str, str, str]]:
        """Return ``[(key, label, value_text), ...]`` for the Settings screen.

        Booleans render as ``on`` / ``off``; cycle fields render their value.
        """
        rows: list[tuple[str, str, str]] = []
        data = self.to_dict()
        for key, label, kind in _SETTING_ROWS:
            value = data[key]
            text = ("on" if value else "off") if kind == "toggle" else str(value)
            rows.append((key, label, text))
        return rows

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict | None) -> "ConsoleSettings":
        """Build settings from a parsed mapping, ignoring unknown keys.

        Only keys matching a declared field are read; everything else is
        dropped. The result is normalized so callers always get valid
        values.
        """
        if not isinstance(data, dict):
            return cls()
        known = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered).normalized()


def settings_path() -> Path:
    """Return the console settings file path (XDG-aware, not created)."""
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "argus" / "console.yml"


def load_settings(path: Path | None = None) -> ConsoleSettings:
    """Load settings from ``path`` (default: the XDG location).

    Returns defaults when the file is missing, empty, unreadable, or not a
    YAML mapping — the console must always start, even from a broken file.
    """
    target = path or settings_path()
    try:
        raw = target.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return ConsoleSettings()
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        return ConsoleSettings()
    return ConsoleSettings.from_dict(data if isinstance(data, dict) else None)


def save_settings(settings: ConsoleSettings, path: Path | None = None) -> Path:
    """Persist ``settings`` to ``path`` (default: the XDG location).

    Creates the parent directory if needed and writes a normalized,
    human-editable YAML document. Returns the path written.
    """
    target = path or settings_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    normalized = settings.normalized()
    target.write_text(
        yaml.safe_dump(normalized.to_dict(), sort_keys=True, default_flow_style=False),
        encoding="utf-8",
    )
    return target
