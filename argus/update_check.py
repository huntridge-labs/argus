"""Background update check — surface a soft notice when a newer argus is available.

A security tool that's months out of date is missing CVE-database
updates, new severity-classification rules, and bug fixes that affect
scan correctness. This module polls PyPI once per day per machine,
compares the published version to the installed one, and prints a
``pip``-style notice at the end of long-running commands when a newer
release exists.

Design constraints (in priority order):

1. **Air-gap friendly.** Silently skip on any network error. Air-gapped
   environments and offline CI runners must not see a tool slowdown,
   error message, or visible failure because PyPI is unreachable.
2. **Privacy-respectful.** One HTTP request per machine per 24 hours,
   cached in ``~/.cache/argus/update-check.json``. The same data PyPI
   already gets from ``pip install argus-security``.
3. **Zero scan-latency cost.** Runs in a daemon thread alongside the
   scan; the result is consumed at end-of-command. The scan was
   already going to take seconds-to-minutes; the update check
   completes in <500ms typically and runs in parallel.
4. **Override-friendly.** Three suppression hooks for different
   audiences:
     * ``ARGUS_NO_UPDATE_CHECK=1`` env var — set once for CI / air-gap
     * ``--no-update-check`` flag — per-invocation
     * ``--quiet`` flag — auto-respects explicit silence
   Plus ``ARGUS_UPDATE_CHECK_URL`` to point at TestPyPI / private
   mirrors when the user knows their distribution channel differs from
   the public PyPI.
5. **Pre-release-aware.** Editable / dev / RC installs auto-skip — a
   contributor on ``0.7.2.dev0+g123abc`` doesn't want to be told
   ``0.7.2`` is "available."
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from argus import __version__

logger = logging.getLogger("argus.update_check")

DEFAULT_PYPI_URL = "https://pypi.org/pypi/argus-security/json"
CACHE_TTL = timedelta(hours=24)
HTTP_TIMEOUT = 2.0  # seconds; keep tight to avoid stalling --quiet runs


def _pypi_url() -> str:
    """Resolve the index URL — env var override wins."""
    return os.environ.get("ARGUS_UPDATE_CHECK_URL", DEFAULT_PYPI_URL)


def _cache_path() -> Path:
    """Locate the on-disk cache file. Honors XDG_CACHE_HOME."""
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "argus" / "update-check.json"


def _is_dev_install() -> bool:
    """Return True for editable / pre-release / dirty installs.

    These users typically don't want update notifications — they're
    on bleeding-edge or experimenting. ``__version__`` strings like
    ``0.7.2.dev0+g123abc`` or ``0.7.2+dirty`` indicate non-release.
    """
    v = __version__
    return any(marker in v for marker in (".dev", "+", "rc"))


def should_check(args=None) -> bool:
    """Honor every suppression hook in order of preference.

    Order matters — env var wins so air-gapped/CI users with one
    persistent setting don't have to add ``--no-update-check`` to
    every invocation.
    """
    if os.environ.get("ARGUS_NO_UPDATE_CHECK"):
        return False
    if args is not None and getattr(args, "no_update_check", False):
        return False
    if args is not None and getattr(args, "quiet", False):
        # User explicitly asked for less output — respect it.
        return False
    if _is_dev_install():
        return False
    return True


def _read_cache() -> Optional[dict]:
    path = _cache_path()
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _write_cache(latest_version: str) -> None:
    path = _cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "latest_version": latest_version,
            }),
            encoding="utf-8",
        )
    except OSError:
        # Cache failure is non-fatal — we just won't cache this round.
        logger.debug("update-check cache write failed", exc_info=True)


def _cache_is_fresh(cache: dict) -> bool:
    try:
        checked_at = datetime.fromisoformat(cache["checked_at"])
    except (KeyError, ValueError, TypeError):
        return False
    return datetime.now(timezone.utc) - checked_at < CACHE_TTL


def fetch_latest_version() -> Optional[str]:
    """Hit PyPI directly. ``None`` on any failure (network, parse, missing)."""
    url = _pypi_url()
    try:
        req = Request(
            url,
            headers={"User-Agent": f"argus-security/{__version__}"},
        )
        with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        version = data.get("info", {}).get("version")
        return version if isinstance(version, str) else None
    except (URLError, json.JSONDecodeError, OSError, ValueError):
        # Air-gap-friendly: every network/parse failure is silent.
        logger.debug("update-check fetch failed for %s", url, exc_info=True)
        return None


def cached_latest_version() -> Optional[str]:
    """Read from cache if fresh; otherwise fetch + write.

    Returns ``None`` only when both the cache miss AND the network
    fetch fail.
    """
    cache = _read_cache()
    if cache and _cache_is_fresh(cache):
        return cache.get("latest_version")

    latest = fetch_latest_version()
    if latest:
        _write_cache(latest)
    return latest


def is_newer(current: str, latest: str) -> bool:
    """``True`` when *latest* > *current*. Falls back to inequality on parse failure."""
    try:
        from packaging.version import parse, InvalidVersion
        try:
            return parse(latest) > parse(current)
        except InvalidVersion:
            return latest != current
    except ImportError:
        # ``packaging`` is a transitive dep of pip+setuptools; this
        # branch is mostly theoretical but keeps the helper robust on
        # exotic minimal environments.
        return latest != current


def format_notice(current: str, latest: str) -> str:
    """Match ``pip``'s notice shape so it reads familiar.

    Two lines, ``[notice]`` prefix, the version transition, and the
    upgrade command. End with a trailing newline so it doesn't bleed
    into a shell prompt.
    """
    return (
        f"\n[notice] A new release of argus-security is available: "
        f"{current} → {latest}\n"
        f"[notice] To update, run: pip install --upgrade argus-security\n"
    )


def get_notice_if_outdated() -> Optional[str]:
    """End-to-end convenience: cached check + comparison + format.

    ``None`` when up-to-date, when the check failed, or when the
    user is on a dev/RC build.
    """
    if _is_dev_install():
        return None
    latest = cached_latest_version()
    if not latest:
        return None
    if not is_newer(__version__, latest):
        return None
    return format_notice(__version__, latest)


# ────────────────────────────────────────────────────────────────────
# Async/background helpers — run alongside the scan, consume at end
# ────────────────────────────────────────────────────────────────────


class BackgroundCheck:
    """Daemon-thread wrapper for ``get_notice_if_outdated``.

    Usage::

        check = start_background_check(args)
        # ... do scan work ...
        if check is not None:
            notice = check.notice()
            if notice:
                print(notice, file=sys.stderr)
    """

    def __init__(self):
        self._notice: Optional[str] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "BackgroundCheck":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _run(self) -> None:
        try:
            self._notice = get_notice_if_outdated()
        except Exception:  # never leak bg-thread exceptions to the user
            logger.debug("update check failed", exc_info=True)
            self._notice = None

    def notice(self, timeout: float = 0.1) -> Optional[str]:
        """Block briefly for the bg thread to finish; return notice or None.

        Default timeout is 100ms — enough for the local-cache-hit path
        to complete, short enough that an unexpected hang doesn't
        delay the user. Network-fetch path completes during the scan
        itself, so by end-of-command the result is already in memory.
        """
        if self._thread:
            self._thread.join(timeout=timeout)
        return self._notice


def start_background_check(args=None) -> Optional[BackgroundCheck]:
    """Kick off the update check in a daemon thread.

    Returns ``None`` when suppressed (env var, flag, dev install, or
    ``--quiet``). Callers should null-check the return value before
    consuming.
    """
    if not should_check(args):
        return None
    return BackgroundCheck().start()
