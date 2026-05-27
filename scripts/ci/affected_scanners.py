#!/usr/bin/env python3
"""Map a git diff to the scanner names it affects — for scoping the
container smoke tests (pre-push hook + PR CI) so we don't pull every
scanner image on every change.

Prints, one per line:
  - the literal ``ALL`` when a cross-cutting file changed (engine,
    containers registry, scanner template, or a package __init__) — those
    affect every scanner's invocation, so the full matrix must run;
  - otherwise the scanner names whose own module files changed (resolved
    via each registered scanner's ``__module__``, so renames like
    ``trivy_iac.py`` → ``trivy-iac`` and ``supply_chain.py`` →
    ``supply-chain`` map correctly);
  - nothing when no scanner/linter code changed (callers skip the smoke).

Usage:
  python -m scripts.ci.affected_scanners [BASE_REF]   # default origin/main
"""

from __future__ import annotations

import subprocess
import sys

# Files whose change can alter how *every* scanner is invoked. A diff
# touching any of these forces the full smoke matrix.
CROSS_CUTTING = frozenset({
    "argus/core/engine.py",
    "argus/containers.py",
    "argus/core/scanner_template.py",
    "argus/scanners/__init__.py",
    "argus/linters/__init__.py",
})


def _module_path_to_scanners() -> dict[str, list[str]]:
    """Map each scanner module's repo-relative path to the scanner names
    it registers (a module can register more than one)."""
    from argus.scanners import SCANNER_REGISTRY

    out: dict[str, list[str]] = {}
    for name, cls in SCANNER_REGISTRY.items():
        path = cls.__module__.replace(".", "/") + ".py"
        out.setdefault(path, []).append(name)
    return out


def changed_files(base_ref: str) -> list[str]:
    """Repo-relative paths changed between base_ref and HEAD (three-dot:
    changes on HEAD's side since the merge base)."""
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
        capture_output=True, text=True, timeout=30,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def affected_scanners(files: list[str]) -> list[str] | str:
    """Return ``"ALL"`` for cross-cutting changes, else the sorted list of
    affected scanner names (possibly empty)."""
    if any(f in CROSS_CUTTING for f in files):
        return "ALL"
    mod_map = _module_path_to_scanners()
    affected: set[str] = set()
    for f in files:
        affected.update(mod_map.get(f, []))
    return sorted(affected)


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    base_ref = argv[0] if argv else "origin/main"
    result = affected_scanners(changed_files(base_ref))
    if result == "ALL":
        print("ALL")
    else:
        for name in result:
            print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
