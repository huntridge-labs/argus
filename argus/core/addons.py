"""Discover installed Argus add-on packages (plugins layered on the core).

Any distribution that registers into one of Argus's plugin entry-point groups is
an "add-on" — for example a commercial extension. Core never needs to know
specific add-on names; this enumerates them *generically* so ``argus --version``
and scan provenance can record the whole installed picture (which extensions were
present when a scan ran), regardless of who shipped them.

Discovery is best-effort and never raises: a failure yields an empty list, since
neither ``--version`` nor a scan should crash because plugin metadata is odd.
"""

from __future__ import annotations

from importlib import metadata

#: Plugin entry-point groups an add-on can register into. Keep in sync with the
#: discovery sites: ``argus.cli`` (cli_commands / console_providers), the browser
#: viewer (viewers.browser_plugins), and the reporter registry (reporters).
ADDON_ENTRY_POINT_GROUPS = (
    "argus.cli_commands",
    "argus.console_providers",
    "argus.viewers.browser_plugins",
    "argus.reporters",
)

#: The core distribution itself — excluded from the add-on list (its version is
#: reported separately). Compared PEP 503-normalized so ``argus_security`` and
#: ``argus-security`` both match.
CORE_DISTRIBUTION = "argus-security"


def _normalize(name: str) -> str:
    return name.replace("_", "-").lower()


def installed_addons() -> list[dict]:
    """Installed distributions that register into Argus plugin groups.

    Returns a list (sorted by name) of ``{"name", "version", "groups"}`` — one
    entry per distribution, excluding the core package. Never raises.
    """
    core = _normalize(CORE_DISTRIBUTION)
    groups_by_dist: dict[str, set[str]] = {}

    for group in ADDON_ENTRY_POINT_GROUPS:
        try:
            eps = metadata.entry_points(group=group)
        except Exception:
            continue
        for ep in eps:
            dist = getattr(getattr(ep, "dist", None), "name", None)
            if not dist or _normalize(dist) == core:
                continue
            groups_by_dist.setdefault(dist, set()).add(group)

    addons: list[dict] = []
    for name in sorted(groups_by_dist):
        try:
            version = metadata.version(name)
        except metadata.PackageNotFoundError:
            version = "unknown"
        addons.append(
            {
                "name": name,
                "version": version,
                "groups": sorted(groups_by_dist[name]),
            }
        )
    return addons
