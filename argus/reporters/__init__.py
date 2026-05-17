"""Argus reporters — output scan results in various formats.

The reporter registry is built dynamically from Python entry-points
under the ``argus.reporters`` group. Built-in reporters are registered
the same way third-party plugins are: their entry-points are declared
in ``pyproject.toml``. There is no special-cased "internal" path.

Discovery semantics:

* **Built-ins always win on name collision.** A package shipping
  ``argus.reporters = "terminal = mypkg:Foo"`` cannot shadow Argus's
  own ``terminal`` reporter — the built-in is used and a warning is
  logged. This keeps `argus scan --format terminal` deterministic
  across environments.

* **First-wins for third-party collisions.** If two third-party
  packages declare the same name, the first one ``importlib.metadata``
  yields wins (deterministic across runs of the same install) and a
  warning is logged. We don't want a silent shadow.

* **Graceful failure.** A plugin that raises on import, fails to
  resolve, or doesn't satisfy the ``Reporter`` protocol is logged and
  skipped. ``argus list`` and ``argus scan`` keep working with
  whatever else loaded successfully.

* **Lazy + cached.** The registry is built on first access and cached
  for the process lifetime. Tests that exercise discovery use
  ``_reset_registry_cache_for_tests()`` to force a rebuild.

Third-party reporter authors: see ``docs/contributing-reporters.md``.
"""

from __future__ import annotations

import importlib.metadata
import logging
from pathlib import Path
from typing import Any, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "argus.reporters"

# Names whose binding to a built-in module is non-negotiable. Even if a
# third-party plugin declares an entry-point with one of these names,
# the built-in version wins and a warning is logged. Populated at import
# time from the ``argus.*`` entry-point values shipped in pyproject.toml.
_BUILTIN_NAMES: set[str] = {
    "terminal",
    "markdown",
    "container_markdown",
    "sarif",
    "json",
    "github",
    "gitlab",
    "junit",
}

# Direct ``module:attr`` paths for the built-in reporters. Used as a
# fallback in ``_load_registry`` when entry-point discovery turns up
# empty — which happens when argus is on ``sys.path`` via
# ``PYTHONPATH`` but isn't ``pip install``-ed, so
# ``importlib.metadata`` has no record of the ``argus.reporters``
# entry-point group. The CI ``security-scan.yml`` workflow runs in
# that shape; without this fallback the validator rejects every
# format in argus.yml and the scan exits with EXIT_ERROR=2 before any
# scanner runs (issue #172).
#
# Keep in sync with the ``[project.entry-points."argus.reporters"]``
# block in pyproject.toml. The names must match ``_BUILTIN_NAMES``.
_BUILTIN_FALLBACKS: dict[str, str] = {
    "terminal": "argus.reporters.terminal:TerminalReporter",
    "markdown": "argus.reporters.markdown:MarkdownReporter",
    "container_markdown": "argus.reporters.container_markdown:ContainerMarkdownReporter",
    "sarif": "argus.reporters.sarif:SarifReporter",
    "json": "argus.reporters.json_report:JsonReporter",
    "github": "argus.reporters.github:GitHubReporter",
    "gitlab": "argus.reporters.gitlab:GitLabReporter",
    "junit": "argus.reporters.junit:JUnitReporter",
}


@runtime_checkable
class Reporter(Protocol):
    """Reporter protocol — every registered reporter must implement this.

    A reporter is any object whose ``.report(summary, output_dir=None)``
    method consumes a ``ScanSummary`` and emits output (terminal, file,
    network, etc.). The ``output_dir`` argument is optional; reporters
    that write files to disk respect it, reporters that only emit to
    stdout / a third-party API ignore it.
    """

    def report(self, summary: Any, output_dir: Optional[Path] = None) -> Any:
        ...


# Registry cache. Built on first call to ``_load_registry()``; reused
# for the rest of the process. Tests force a rebuild via
# ``_reset_registry_cache_for_tests()`` so the tests stay independent.
_REGISTRY_CACHE: dict[str, type] | None = None


def _is_builtin_entry_point(ep: importlib.metadata.EntryPoint) -> bool:
    """Return True when the entry-point's value points at our own package.

    We use the ``value`` (the ``module:attr`` string) rather than the
    distribution name because a developer may install argus from a local
    checkout where the dist name resolution is brittle, and because the
    entry-point value is the same regardless of how the package got onto
    sys.path.
    """
    return ep.value.startswith("argus.reporters.")


def _load_one(ep: importlib.metadata.EntryPoint) -> type | None:
    """Resolve a single entry-point to a reporter class, or None on failure.

    Failures are logged at WARNING and the loader returns ``None`` so the
    overall registry build keeps making progress. We deliberately catch
    a broad ``Exception`` here: a buggy plugin can raise *anything* on
    import, and a single broken plugin must not break ``argus list`` or
    ``argus scan`` for users who have other reporters available.
    """
    try:
        cls = ep.load()
    except Exception as exc:  # noqa: BLE001 — broad catch is the point
        logger.warning(
            "Failed to load reporter plugin %r (%s): %s",
            ep.name,
            ep.value,
            exc,
        )
        return None

    # Validate protocol shape. We can't fully runtime-check a Protocol
    # for unbound classes, so we instantiate and check the instance.
    # A reporter that fails on no-arg construction is also useless to
    # us — log + skip.
    try:
        instance = cls()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Reporter plugin %r (%s) raised on instantiation: %s",
            ep.name,
            ep.value,
            exc,
        )
        return None

    if not isinstance(instance, Reporter):
        logger.warning(
            "Reporter plugin %r (%s) does not implement the Reporter "
            "protocol (.report(summary, output_dir=None)); skipping",
            ep.name,
            ep.value,
        )
        return None

    return cls


def _iter_entry_points() -> list[importlib.metadata.EntryPoint]:
    """Return entry-points for the ``argus.reporters`` group.

    Wrapped in its own helper so tests can monkeypatch a deterministic
    set of entry-points without monkeypatching ``importlib.metadata``
    directly.
    """
    eps = importlib.metadata.entry_points()
    # Python 3.10+ returns an EntryPoints object with .select().
    # Earlier versions returned a dict — but we require Python ≥ 3.11
    # (see pyproject.toml), so .select() is always available.
    return list(eps.select(group=ENTRY_POINT_GROUP))


def _load_registry() -> dict[str, type]:
    """Build the reporter name → class registry from entry-points.

    Two-pass build to honor the "built-ins always win" rule:

    1. Walk all entry-points. Built-ins get registered unconditionally;
       a third-party entry-point with the same name is rejected with a
       warning.
    2. For names not claimed by a built-in, the first-loaded plugin
       wins; subsequent ones with the same name are rejected with a
       warning.
    """
    registry: dict[str, type] = {}
    for ep in _iter_entry_points():
        is_builtin = _is_builtin_entry_point(ep)

        if ep.name in registry:
            # Existing entry. Built-ins shadow plugins; plugins yield
            # to built-ins; plugin-vs-plugin is first-wins.
            existing_is_builtin = ep.name in _BUILTIN_NAMES and not is_builtin
            if is_builtin and ep.name not in _BUILTIN_NAMES:
                # Shouldn't happen — names in pyproject.toml's
                # entry-points block are the source of truth for
                # ``_BUILTIN_NAMES``. Guarded for completeness.
                _BUILTIN_NAMES.add(ep.name)

            if is_builtin:
                # Replace whatever's there with the built-in.
                cls = _load_one(ep)
                if cls is not None:
                    logger.warning(
                        "Reporter name %r was shadowed by a third-party "
                        "plugin; built-in implementation takes precedence",
                        ep.name,
                    )
                    registry[ep.name] = cls
            else:
                # Plugin trying to claim a name that's already taken.
                if existing_is_builtin or ep.name in _BUILTIN_NAMES:
                    logger.warning(
                        "Reporter plugin %r (%s) ignored: name conflicts "
                        "with a built-in reporter",
                        ep.name,
                        ep.value,
                    )
                else:
                    logger.warning(
                        "Reporter plugin %r (%s) ignored: name already "
                        "registered by an earlier plugin",
                        ep.name,
                        ep.value,
                    )
            continue

        cls = _load_one(ep)
        if cls is not None:
            registry[ep.name] = cls

    # Built-in fallback — see ``_BUILTIN_FALLBACKS`` docstring. Any
    # built-in name not covered by entry-points loads directly from its
    # canonical module so the registry works for bare PYTHONPATH
    # installs (issue #172). Matches the SCANNER_REGISTRY / LINTER_REGISTRY
    # shape, which has never relied on entry-points.
    import importlib
    for name, target in _BUILTIN_FALLBACKS.items():
        if name in registry:
            continue
        module_path, _, attr = target.partition(":")
        try:
            module = importlib.import_module(module_path)
            cls = getattr(module, attr)
        except (ImportError, AttributeError) as exc:
            logger.warning(
                "Built-in reporter %r could not be loaded from %s: %s",
                name, target, exc,
            )
            continue
        registry[name] = cls

    return registry


def _get_registry() -> dict[str, type]:
    """Return the cached registry, building it on first call."""
    global _REGISTRY_CACHE
    if _REGISTRY_CACHE is None:
        _REGISTRY_CACHE = _load_registry()
    return _REGISTRY_CACHE


def _reset_registry_cache_for_tests() -> None:
    """Drop the cached registry so the next call rebuilds it.

    Tests that monkeypatch ``_iter_entry_points`` call this in
    ``setup``/``teardown`` so each test sees a freshly-built registry.
    Not part of the public API.
    """
    global _REGISTRY_CACHE
    _REGISTRY_CACHE = None


def get_reporter(name: str) -> Reporter:
    """Get a reporter instance by name.

    Raises ``ValueError`` if the name isn't registered.
    """
    registry = _get_registry()
    cls = registry.get(name)
    if not cls:
        available = ", ".join(sorted(registry))
        raise ValueError(f"Unknown reporter: {name}. Available: {available}")
    return cls()


def available_reporters() -> list[str]:
    """Return list of registered reporter names (sorted for stable output)."""
    return sorted(_get_registry().keys())


# Backwards-compatibility alias. Prior to the entry-points refactor
# ``REPORTER_REGISTRY`` was a hardcoded ``dict`` literal at module
# import time; some consumers reach for it directly. We expose a thin
# read-only view backed by the lazy cache so legacy
# ``from argus.reporters import REPORTER_REGISTRY`` still works.
class _RegistryProxy:
    """Read-only mapping that defers to the cached registry."""

    def __getitem__(self, key: str) -> type:
        return _get_registry()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return _get_registry().get(key, default)

    def __contains__(self, key: object) -> bool:
        return key in _get_registry()

    def __iter__(self):
        return iter(_get_registry())

    def __len__(self) -> int:
        return len(_get_registry())

    def keys(self):
        return _get_registry().keys()

    def values(self):
        return _get_registry().values()

    def items(self):
        return _get_registry().items()


REPORTER_REGISTRY = _RegistryProxy()


# The single canonical scan artifact. ``argus-results.json`` is consumed
# by the audit manifest, both viewers (terminal + browser), the
# ``argus report`` subcommand, and any downstream tooling built on the
# SDK. Treating it as always-emitted decouples its existence from
# user-configured ``reporting.formats``: that list now means "which
# *additional* human-readable reports to emit alongside the canonical
# JSON," not "which artifacts exist at all." Eliminates the failure
# mode where a config like ``formats: [terminal, sarif]`` silently
# breaks ``argus view``.
CANONICAL_FORMAT = "json"


def ensure_canonical_json(formats: list[str]) -> list[str]:
    """Return the format list with the canonical JSON output guaranteed.

    Idempotent — if the user already lists ``json`` we don't add a
    duplicate (which would write the file twice). Order is preserved
    so the user's terminal/markdown/sarif reports still print in the
    sequence they configured; the canonical JSON is appended at the
    end so it's always the last reporter to run (its dict-dump output
    isn't influenced by side-effects of earlier reporters).
    """
    if CANONICAL_FORMAT in formats:
        return list(formats)
    return [*formats, CANONICAL_FORMAT]
