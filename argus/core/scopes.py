"""Finding scope taxonomy — group findings into report scopes.

Three scopes, derived from each scanner's ``category``:

* ``lint``         — linters (style / syntax diagnostics)
* ``supply-chain`` — SCA / dependency / container composition + the
                     supply-chain scanner (the source of SBOM / VEX artifacts)
* ``security``     — everything else (SAST, secrets, IaC, DAST, malware, ...)

Used to organize the report output directory by scope (``security/`` ``lint/``
``supply-chain/``) alongside the canonical aggregate ``argus-results.json`` at
the output-dir root. The mapping is registry-driven (each scanner declares a
``category``) with a scanner-name-prefix fallback, so a newly added scanner is
classified without touching this module.
"""

from __future__ import annotations

from argus.core.models import Finding

SCOPE_SECURITY = "security"
SCOPE_LINT = "lint"
SCOPE_SUPPLY_CHAIN = "supply-chain"
SCOPES = (SCOPE_SECURITY, SCOPE_LINT, SCOPE_SUPPLY_CHAIN)

_LINT_CATEGORIES = frozenset({"linter", "linting"})
_SUPPLY_CHAIN_CATEGORIES = frozenset({"sca", "supply-chain", "container"})


def scope_for_category(category: str, scanner_name: str = "") -> str:
    """Map a scanner ``category`` (+ name fallback) to a report scope."""
    category = (category or "").lower()
    name = (scanner_name or "").lower()
    if category in _LINT_CATEGORIES or name.startswith(("lint-", "lint_")):
        return SCOPE_LINT
    if category in _SUPPLY_CHAIN_CATEGORIES:
        return SCOPE_SUPPLY_CHAIN
    return SCOPE_SECURITY


_scanner_scope_map: dict[str, str] | None = None


def _build_scanner_scope_map() -> dict[str, str]:
    """``scanner-name -> scope``, derived from the live registry categories."""
    mapping: dict[str, str] = {}
    try:
        from argus.scanners import SCANNER_REGISTRY
    except Exception:  # noqa: BLE001 — registry load is best-effort
        return mapping
    for name, cls in SCANNER_REGISTRY.items():
        mapping[name.lower()] = scope_for_category(getattr(cls, "category", ""), name)
    return mapping


def scope_for_finding(finding: Finding) -> str:
    """Return the report scope for ``finding`` from its originating scanner.

    Registry-derived where the scanner is known; otherwise a name-prefix
    fallback (``lint-*`` → lint, else security)."""
    global _scanner_scope_map
    if _scanner_scope_map is None:
        _scanner_scope_map = _build_scanner_scope_map()
    name = (finding.scanner or "").lower()
    return _scanner_scope_map.get(name) or scope_for_category("", name)


def reset_scope_cache() -> None:
    """Clear the cached scanner→scope map (tests that mutate the registry)."""
    global _scanner_scope_map
    _scanner_scope_map = None
