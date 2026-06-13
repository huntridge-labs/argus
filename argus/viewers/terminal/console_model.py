"""Pure model + content for the Argus Console home screen.

Textual-free on purpose (same rule as ``run_discovery`` / ``findings_view``):
the banner, the menu definition, the home-screen status summary, and the
custom-theme palette are all plain data / pure functions, so they're
unit-testable in CI without the ``[terminal]`` extra. ``console.py`` (the
Textual App and screens) consumes everything here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from argus.core.findings_view import SEVERITY_GLYPH
from argus.core.run_discovery import discover_runs


# Block-letter wordmark shown on the home screen. Kept deliberately compact
# so it fits an 80-column terminal with room for the tagline beside it.
ARGUS_BANNER = r"""
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
"""

TAGLINE = "supply-chain security scanning, in your terminal"


@dataclass(frozen=True)
class MenuItem:
    """One home-screen launcher entry."""

    key: str          # stable id used for dispatch + OptionList option id
    label: str        # what the user sees
    hint: str         # one-line description under / beside the label
    icon: str = "›"   # leading glyph


# The home launcher. Order is the on-screen order. ``scan`` / ``findings`` /
# ``settings`` / ``docs`` are fully wired in this phase; ``configure`` opens
# argus.yml in the user's editor and ``init`` streams ``argus init`` — both
# real, with the richer form-editor / wizard screens tracked as later phases
# in docs/developer/CONSOLE-ROADMAP.md.
MENU: tuple[MenuItem, ...] = (
    MenuItem("scan", "Run a scan", "Run argus scan and watch it live", "⚡"),
    MenuItem("findings", "View findings", "Browse and triage the latest results", "🔎"),
    MenuItem("configure", "Configure", "Edit argus.yml in your editor", "⚙"),
    MenuItem("init", "Initialize", "Detect the project and generate argus.yml", "✨"),
    MenuItem("settings", "Settings", "Theme, colours, animations, notifications", "🎛"),
    MenuItem("docs", "Help & docs", "Keybindings and where to learn more", "📖"),
    MenuItem("quit", "Quit", "Leave the console", "✕"),
)


# Custom "argus-dark" theme palette — a deep slate base with a cyan accent,
# registered against Textual's Theme at app start. Plain hex so this stays
# textual-free; ``console.py`` maps it onto a ``textual.theme.Theme``.
ARGUS_DARK_PALETTE: dict[str, str] = {
    "primary": "#38bdf8",      # sky/cyan — the Argus accent
    "secondary": "#7dd3fc",
    "accent": "#38bdf8",
    "background": "#0b1220",   # near-black slate
    "surface": "#111a2b",
    "panel": "#16233b",
    "success": "#4ade80",
    "warning": "#fbbf24",
    "error": "#f87171",
    "foreground": "#e2e8f0",
}

# Accent-name → hex, for the Settings accent picker. Names match
# ``console_config.ACCENTS``.
ACCENT_HEX: dict[str, str] = {
    "cyan": "#38bdf8",
    "green": "#4ade80",
    "magenta": "#e879f9",
    "blue": "#60a5fa",
    "yellow": "#fbbf24",
    "red": "#f87171",
    "orange": "#fb923c",
    "purple": "#a78bfa",
}


def accent_hex(name: str) -> str:
    """Return the hex for an accent name, defaulting to cyan."""
    return ACCENT_HEX.get(name, ACCENT_HEX["cyan"])


def home_status(launch_root: Path, *, config_path: Path | None = None) -> dict:
    """Summarise project state for the home screen's status panel.

    Pure file I/O + ``discover_runs`` (no Textual). Returns::

        {
            "run_count":      int,
            "latest_label":   str | None,
            "latest_count":   int | None,
            "latest_severity": Severity | None,
            "config_present": bool,
        }

    so the home screen can render "last run: <label> — N findings (worst:
    CRITICAL)" and nudge the user toward Init when no config exists.
    """
    runs = discover_runs(launch_root)
    latest = runs[0] if runs else None
    present = bool(config_path and config_path.is_file())
    return {
        "run_count": len(runs),
        "latest_label": latest["label"] if latest else None,
        "latest_count": latest["count"] if latest else None,
        "latest_severity": latest["worst_severity"] if latest else None,
        "config_present": present,
    }


def status_line(status: dict) -> str:
    """Render ``home_status`` output as a single human line for the panel."""
    if not status.get("config_present"):
        cfg = "no argus.yml yet — pick Initialize to create one"
    else:
        cfg = "argus.yml found"
    if status.get("run_count"):
        label = status.get("latest_label") or "?"
        count = status.get("latest_count") or 0
        sev = status.get("latest_severity")
        glyph = SEVERITY_GLYPH.get(sev, "✓ none") if sev else "✓ none"
        runs = f"latest run {label} · {count} findings · worst {glyph}"
    else:
        runs = "no scan runs found yet — pick Run a scan"
    return f"{cfg}   ·   {runs}"
