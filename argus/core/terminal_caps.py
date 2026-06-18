"""Terminal capability detection (Phase 9 — graphics foundation).

Pure, dependency-free, UI-free. Detects what the host terminal can do —
inline-image graphics protocol (Kitty / iTerm2 / Sixel), OSC 8 hyperlinks,
and 24-bit truecolor — from environment variables alone (no escape-sequence
probing, which would be unsafe to do unsolicited).

This is the foundation the richer graphics work gates on: inline raster
rendering (a `textual-image`-backed logo / dependency-graph image / QR code)
is a capability-gated opt-in that builds on `detect_graphics` here, with a
clean Unicode/ASCII fallback whenever the terminal can't do pixels. Keeping
detection separate and dependency-free means the fallback path — the common
case — carries no extra dependency surface, the right default for a
supply-chain tool.
"""

from __future__ import annotations

import os
from typing import Mapping

GRAPHICS_NONE = "none"
GRAPHICS_KITTY = "kitty"
GRAPHICS_ITERM = "iterm"
GRAPHICS_SIXEL = "sixel"


def _env(env: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if env is None else env


def detect_graphics(env: Mapping[str, str] | None = None) -> str:
    """Best-effort inline-image protocol for the terminal.

    Returns one of ``GRAPHICS_KITTY`` / ``GRAPHICS_ITERM`` / ``GRAPHICS_SIXEL``
    / ``GRAPHICS_NONE`` from env hints only. Kitty's protocol (also spoken by
    Ghostty/WezTerm) is preferred where detected; iTerm2 has its own inline
    image protocol; a few terminals do Sixel.
    """
    e = _env(env)
    term = (e.get("TERM") or "").lower()
    term_program = (e.get("TERM_PROGRAM") or "").lower()

    if e.get("KITTY_WINDOW_ID") or term.startswith("xterm-kitty") or "kitty" in term:
        return GRAPHICS_KITTY
    if "ghostty" in term or term_program == "ghostty":
        return GRAPHICS_KITTY
    if term_program == "wezterm" or e.get("WEZTERM_PANE"):
        return GRAPHICS_KITTY
    if term_program == "iterm.app" or e.get("ITERM_SESSION_ID"):
        return GRAPHICS_ITERM
    if term in ("foot", "xterm-foot") or "contour" in term_program or e.get("MLTERM"):
        return GRAPHICS_SIXEL
    return GRAPHICS_NONE


def supports_graphics(env: Mapping[str, str] | None = None) -> bool:
    """True when the terminal can render inline pixel images."""
    return detect_graphics(env) != GRAPHICS_NONE


def supports_hyperlinks(env: Mapping[str, str] | None = None) -> bool:
    """True when the terminal is likely to honour OSC 8 hyperlinks.

    Conservative: the dumb terminal and the Linux text console don't; an
    explicit ``NO_HYPERLINKS`` opt-out is respected. Everything else with a
    real ``TERM`` is assumed capable (OSC 8 is widely supported and degrades
    to plain text where it isn't).
    """
    e = _env(env)
    if e.get("NO_HYPERLINKS"):
        return False
    term = (e.get("TERM") or "").lower()
    return bool(term) and term not in ("dumb", "linux")


def supports_truecolor(env: Mapping[str, str] | None = None) -> bool:
    """True when the terminal advertises 24-bit colour via ``COLORTERM``."""
    return (_env(env).get("COLORTERM") or "").lower() in ("truecolor", "24bit")


def capability_summary(env: Mapping[str, str] | None = None) -> str:
    """One-line human summary for a Help / diagnostics screen."""
    graphics = detect_graphics(env)
    links = "yes" if supports_hyperlinks(env) else "no"
    color = "yes" if supports_truecolor(env) else "no"
    return f"graphics={graphics} · hyperlinks={links} · truecolor={color}"
