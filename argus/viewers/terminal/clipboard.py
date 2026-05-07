"""Clipboard helper for the terminal viewer.

Triage workflows often want to drop a list of CVE IDs into a bug-tracker
comment. The TUI binds ``c`` to "copy selected CVEs" — this module is the
testable layer behind that binding.

Design choice: prefer ``pyperclip`` when it's installed (cross-platform,
already a transitive dep on many machines), otherwise shell out to the
platform-native CLI:

- macOS  → ``pbcopy``
- Linux  → ``xclip -selection clipboard``, then ``wl-copy`` for Wayland
- Windows → ``clip``

Each strategy is wrapped in a function returning ``(success, mechanism)``
so the caller can show a meaningful toast. When nothing works we return
``(False, None)`` rather than raising — the UI surfaces that as a
graceful "clipboard unavailable" toast instead of crashing the TUI.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Callable


# ---------------------------------------------------------------------------
# Strategy implementations — each returns True on success, False otherwise.
# ---------------------------------------------------------------------------

def _try_pyperclip(text: str) -> bool:
    """Use the ``pyperclip`` library if it's installed.

    pyperclip is intentionally an optional import; users who don't have
    it installed will exercise the shell-out fallbacks below.
    """
    try:
        import pyperclip  # type: ignore[import-not-found]
    except ImportError:
        return False
    try:
        pyperclip.copy(text)
        return True
    except Exception:
        # pyperclip raises ``PyperclipException`` when no backend is
        # available on the platform (e.g. headless Linux without xclip).
        # Fall through to the shell-out chain so the user still gets a
        # working copy when one of those tools is installed.
        return False


def _try_subprocess(argv: list[str], text: str) -> bool:
    """Pipe ``text`` into the given subprocess argv.

    Returns False if the binary isn't on PATH or the process exits
    non-zero. Never raises — the goal is "did it work?", not
    "what went wrong".
    """
    if not shutil.which(argv[0]):
        return False
    try:
        result = subprocess.run(
            argv,
            input=text,
            text=True,
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _platform_strategies() -> list[tuple[str, Callable[[str], bool]]]:
    """Return ordered ``(label, strategy)`` pairs for the current platform.

    pyperclip first (works everywhere it works), then platform-native
    CLI tools. The label is what we surface in the toast so users know
    which mechanism succeeded — useful when debugging "did it actually
    end up in the system clipboard or just the Wayland one?".
    """
    strategies: list[tuple[str, Callable[[str], bool]]] = [
        ("pyperclip", _try_pyperclip),
    ]
    if sys.platform == "darwin":
        strategies.append(
            ("pbcopy", lambda t: _try_subprocess(["pbcopy"], t)),
        )
    elif sys.platform.startswith("linux"):
        # X11 first (still the dominant default for SSH-able Linux),
        # then Wayland for users on a Wayland session without xclip
        # installed.
        strategies.append(
            ("xclip", lambda t: _try_subprocess(
                ["xclip", "-selection", "clipboard"], t,
            )),
        )
        strategies.append(
            ("wl-copy", lambda t: _try_subprocess(["wl-copy"], t)),
        )
    elif sys.platform == "win32":
        strategies.append(
            ("clip", lambda t: _try_subprocess(["clip"], t)),
        )
    return strategies


def copy_to_clipboard(text: str) -> tuple[bool, str | None]:
    """Try every available strategy in order; return (success, mechanism).

    On success, ``mechanism`` is the label of the strategy that worked
    (``"pyperclip"``, ``"pbcopy"``, …). On failure, ``mechanism`` is
    ``None`` and the caller should surface a "no clipboard mechanism
    available" toast.
    """
    for label, strategy in _platform_strategies():
        if strategy(text):
            return True, label
    return False, None


# ---------------------------------------------------------------------------
# Finding-specific helper — produces the exact "one CVE per line" payload
# the ``c`` keybinding ships to the clipboard.
# ---------------------------------------------------------------------------

def format_findings_for_clipboard(findings) -> str:
    """Build the multi-line clipboard payload from a list of findings.

    Rule per finding:
    - If the finding has a CVE → emit the CVE ID.
    - Otherwise → emit ``<scanner>:<id>`` so the row is still
      identifiable in the bug tracker.

    Order matches the input list so the user's selection order survives
    into the paste. Duplicates are preserved — if the same CVE appears
    on multiple selected rows (cross-product, multi-scanner), the user
    asked for it; deduping silently would surprise them.
    """
    lines: list[str] = []
    for f in findings:
        cve = getattr(f, "cve", None)
        if cve:
            lines.append(cve)
        else:
            scanner = getattr(f, "scanner", None) or "unknown"
            fid = getattr(f, "id", None) or "unknown"
            lines.append(f"{scanner}:{fid}")
    return "\n".join(lines)
