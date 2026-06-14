"""UI-free system readiness checks for the Console home (go/no-go chip).

Answers "can I actually run a scan right now, and with what?" before the user
hits a wall like "Docker isn't running". Pure logic over injectable probes so
it's unit-testable without a real Docker daemon or installed tools; the Console
renders the result as a one-line chip (computed in a background worker so the
home stays instant) with an Enter-to-expand modal.

Three checks:

* **Docker** — daemon running / installed-but-stopped / not installed. Only
  *blocking* when the effective execution backend needs it and there's no
  local fallback.
* **Local tools** — how many of the configured scanners are runnable as local
  binaries (each scanner's ``is_available()``).
* **Scanner images** — best-effort: how many cached Argus container images
  match a published release digest (genuine, unmodified tooling). Skipped when
  Docker isn't running.

The overall verdict is the worst actionable state: ``ok`` (●), ``warn`` (▲),
or ``down`` (✖).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional

# A representative set of common local-binary security scanners for the
# readiness "tools" check — kept small so the check stays fast (one
# ``--version`` subprocess each) and relevant. Not exhaustive; the chip is a
# readiness signal, not a full inventory.
COMMON_SCANNERS = ["bandit", "gitleaks", "osv", "checkov", "trivy-iac"]

# Verdict ranking — higher is worse, so the overall verdict is the max.
_OK = "ok"
_WARN = "warn"
_DOWN = "down"
_RANK = {_OK: 0, _WARN: 1, _DOWN: 2}


@dataclass(frozen=True)
class StatusCheck:
    """One readiness check.

    ``ok`` is tri-state: True (good), False (a problem), None (not applicable
    / unknown — e.g. the image check when Docker is off). ``blocking`` marks a
    failure that stops scanning outright (drives the ``down`` verdict).
    """

    key: str
    label: str
    ok: Optional[bool]
    detail: str
    remediation: str = ""
    blocking: bool = False

    @property
    def verdict(self) -> str:
        if self.ok is True or self.ok is None:
            return _OK
        return _DOWN if self.blocking else _WARN


@dataclass(frozen=True)
class SystemStatus:
    """Aggregate readiness — a verdict plus the per-check breakdown."""

    checks: list[StatusCheck] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return max(
            (c.verdict for c in self.checks), key=lambda v: _RANK[v], default=_OK,
        )

    @property
    def glyph(self) -> str:
        return {"ok": "●", "warn": "▲", "down": "✖"}[self.verdict]

    @property
    def summary(self) -> str:
        """A short chip message — the headline problem, or "ready"."""
        if self.verdict == _OK:
            return "System ready"
        # Lead with the worst (blocking first, then warnings).
        ranked = sorted(
            (c for c in self.checks if c.verdict != _OK),
            key=lambda c: _RANK[c.verdict], reverse=True,
        )
        return ranked[0].detail if ranked else "System ready"


# --------------------------------------------------------------------------
# Probes — real implementations, each injectable for tests.
# --------------------------------------------------------------------------

def probe_docker() -> str:  # pragma: no cover - subprocess edge
    """Return ``"running"`` / ``"stopped"`` / ``"absent"`` for the Docker daemon.

    ``absent`` when the ``docker`` CLI isn't on PATH; otherwise ``docker info``
    decides running vs. installed-but-not-started. Best-effort and bounded —
    any error / timeout reads as ``stopped`` rather than raising.
    """
    if shutil.which("docker") is None:
        return "absent"
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return "stopped"
    return "running" if result.returncode == 0 else "stopped"


def probe_local_tools(scanner_names: list[str]) -> dict[str, bool]:  # pragma: no cover - subprocess edge
    """Map each scanner name to whether its tool is available as a local binary.

    Best-effort: a scanner that can't be instantiated or whose availability
    check raises is treated as unavailable rather than crashing the status.
    """
    from argus.scanners import get_scanner

    out: dict[str, bool] = {}
    for name in scanner_names:
        try:
            out[name] = bool(get_scanner(name)().is_available())
        except Exception:
            out[name] = False
    return out


def probe_cached_image_digests() -> set[str]:  # pragma: no cover - subprocess edge
    """Return ``sha256:...`` digests of Argus images cached locally.

    ``docker images --digests`` parsed best-effort; empty set on any error or
    when Docker isn't running (the caller skips the image check then).
    """
    try:
        result = subprocess.run(
            ["docker", "images", "--digests", "--format", "{{.Digest}}"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if result.returncode != 0:
        return set()
    return {
        line.strip() for line in result.stdout.splitlines()
        if line.strip().startswith("sha256:")
    }


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------

def _docker_check(state: str, *, backend: str, local_tool_count: int) -> StatusCheck:
    if state == "running":
        return StatusCheck(
            "docker", "Docker", True, "Docker daemon is running",
        )
    needs_docker = backend == "docker" or (backend == "auto" and local_tool_count == 0)
    if state == "absent":
        return StatusCheck(
            "docker", "Docker", None if not needs_docker else False,
            "Docker not installed",
            remediation="Install Docker, or run with local tools "
                        "(execution.backend: local).",
            blocking=needs_docker,
        )
    # stopped
    return StatusCheck(
        "docker", "Docker", False, "Docker is installed but not running",
        remediation="Start Docker Desktop / the daemon, or set "
                    "execution.backend: local to use local tools.",
        blocking=needs_docker,
    )


def _tools_check(availability: dict[str, bool]) -> StatusCheck:
    total = len(availability)
    have = sum(1 for ok in availability.values() if ok)
    if total == 0:
        return StatusCheck("tools", "Local tools", None, "No scanners configured")
    if have == total:
        return StatusCheck(
            "tools", "Local tools", True, f"All {total} scanners available locally",
        )
    missing = sorted(n for n, ok in availability.items() if not ok)
    return StatusCheck(
        "tools", "Local tools", False,
        f"{have}/{total} scanners available locally",
        remediation="Missing: " + ", ".join(missing)
                    + " — install them, or run those scanners via Docker.",
    )


def _images_check(cached: set[str], published: set[str]) -> StatusCheck:
    matched = cached & published
    if not cached:
        return StatusCheck(
            "images", "Scanner images", None,
            "No Argus images cached (pulled on first containerized scan)",
        )
    if matched:
        return StatusCheck(
            "images", "Scanner images", True,
            f"{len(matched)} cached Argus image(s) match a published release",
        )
    return StatusCheck(
        "images", "Scanner images", False,
        "Cached Argus images don't match any published release digest",
        remediation="Re-pull the official images, or verify the registry — "
                    "a mismatch can mean a rebuilt / overridden image.",
    )


def effective_backend(config_path: object = None) -> str:
    """Best-effort ``execution.backend`` (``auto`` / ``local`` / ``docker``).

    Defaults to ``auto`` when there's no config or it can't be parsed, so the
    chip works before ``argus init`` has run.
    """
    try:
        from argus.core.config import ArgusConfig
        cfg = ArgusConfig.load(config_path) if config_path else ArgusConfig.load()
        return cfg.execution.backend or "auto"
    except Exception:
        return "auto"


def compute_status(
    *,
    scanner_names: list[str],
    backend: str = "auto",
    docker_probe: Callable[[], str] = probe_docker,
    tools_probe: Callable[[list[str]], dict[str, bool]] = probe_local_tools,
    cached_digests_probe: Callable[[], set[str]] = probe_cached_image_digests,
    published_digests: Optional[set[str]] = None,
) -> SystemStatus:
    """Assemble a :class:`SystemStatus` from the probes.

    All probes are injectable so tests run without Docker or installed tools.
    ``backend`` is the effective ``execution.backend`` (``auto`` / ``local`` /
    ``docker``) — it decides whether a stopped/absent Docker is *blocking*.
    The image check only runs when Docker is up.
    """
    availability = tools_probe(scanner_names)
    local_count = sum(1 for ok in availability.values() if ok)

    docker_state = docker_probe()
    checks = [
        _docker_check(docker_state, backend=backend, local_tool_count=local_count),
        _tools_check(availability),
    ]

    if docker_state == "running":
        if published_digests is None:
            from argus.core.toolchain import _published_argus_digests
            published_digests = _published_argus_digests()
        checks.append(_images_check(cached_digests_probe(), published_digests))

    return SystemStatus(checks=checks)
