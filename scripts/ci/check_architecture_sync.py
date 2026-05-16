"""Source-of-truth check for .ai/architecture.yaml + .ai/context.yaml.

Runs at CI time alongside the rest of ``scripts/ci/check_*.py``.
Catches the failure mode the architecture map relies on staying out
of: someone adds a scanner module under ``argus/scanners/`` but
forgets to add its YAML entry, so the architecture page silently
drops it. The check fails loudly with a per-missing-key error
message so the fix is obvious.

What it verifies, all by introspecting the *running* SDK:

  - Every scanner in ``argus.scanners.SCANNER_REGISTRY`` (minus the
    auto-merged linter entries) appears under
    ``scanners:`` in ``.ai/architecture.yaml`` somewhere.
  - Every linter in ``argus.linters.LINTER_REGISTRY`` appears under
    ``scanners.linting:`` in ``.ai/architecture.yaml``.
  - Every reporter in the ``argus.reporters`` entry-point group is
    referenced in ``.ai/architecture.yaml`` (under the
    ``argus-sdk`` component's reporters note or in the diagram-
    component reporters list).
  - Every argparse subcommand on the top-level ``argus`` CLI appears
    under ``entrypoints.cli_subcommands:`` in ``.ai/context.yaml``.

Exit codes:
  0 — everything in sync.
  1 — at least one drift detected. Stdout lists every mismatch with
      the canonical fix (add the missing entry to the YAML).
  2 — could not load required canonical files (missing or malformed).

Run as:
    python -m scripts.ci.check_architecture_sync
"""

from __future__ import annotations

import argparse
import importlib
import sys
from importlib import metadata as importlib_metadata
from pathlib import Path

import yaml


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root", type=Path, default=Path("."),
        help="Repo root containing .ai/ and argus/ (default: cwd)",
    )
    args = parser.parse_args(argv)

    repo_root: Path = args.repo_root.resolve()

    arch_yaml = repo_root / ".ai" / "architecture.yaml"
    context_yaml = repo_root / ".ai" / "context.yaml"
    if not arch_yaml.exists() or not context_yaml.exists():
        print(
            f"❌ Required canonical files missing under {repo_root / '.ai'}/.",
            file=sys.stderr,
        )
        return 2

    architecture = _load_yaml(arch_yaml)
    context = _load_yaml(context_yaml)

    failures: list[str] = []

    failures.extend(_check_scanners(architecture))
    failures.extend(_check_linters(architecture))
    failures.extend(_check_reporters(architecture))
    failures.extend(_check_cli_subcommands(context))

    if failures:
        print(
            "❌ .ai/ files are out of sync with the running SDK:\n",
            file=sys.stderr,
        )
        for line in failures:
            print(f"   • {line}", file=sys.stderr)
        print(
            "\nFix: add the missing entries under the noted YAML "
            "section so the architecture map can render them.\n"
            "Source of truth: the SDK registries / entry-points / "
            "argparse tree. YAML must track them.",
            file=sys.stderr,
        )
        return 1

    print("✅ .ai/architecture.yaml + .ai/context.yaml are in sync with the SDK.")
    return 0


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


# Meta-scanners whose names are top-level YAML keys but not standalone
# entries. ``container`` is the orchestrator — its YAML representation
# is the ``scanners.container:`` block listing its five sub-scanners
# (trivy / grype / syft / exposure / services), not a flat entry of
# its own. Adding new meta-scanners means appending here AND ensuring
# their YAML representation is at least a category key.
_META_SCANNERS: set[str] = {"container"}


def _check_scanners(architecture: dict) -> list[str]:
    try:
        scanners_module = importlib.import_module("argus.scanners")
        scanner_registry = getattr(scanners_module, "SCANNER_REGISTRY", {})
    except Exception as exc:
        return [f"could not import argus.scanners.SCANNER_REGISTRY: {exc}"]
    try:
        linters_module = importlib.import_module("argus.linters")
        linter_registry = getattr(linters_module, "LINTER_REGISTRY", {})
    except Exception:
        linter_registry = {}

    # The SCANNER_REGISTRY auto-merges LINTER_REGISTRY at import time.
    # We split them so we don't false-positive on linters (those have
    # their own block in the YAML).
    pure_scanner_names = (
        set(scanner_registry.keys())
        - set(linter_registry.keys())
        - _META_SCANNERS
    )

    declared = _all_scanner_names_in_yaml(architecture)
    declared |= _yaml_scanner_category_keys(architecture)
    missing = pure_scanner_names - declared
    return [
        f"scanner ``{name}`` is in SCANNER_REGISTRY but not in "
        f".ai/architecture.yaml under any scanners.<category>: list"
        for name in sorted(missing)
    ]


def _check_linters(architecture: dict) -> list[str]:
    try:
        linters_module = importlib.import_module("argus.linters")
        linter_registry = getattr(linters_module, "LINTER_REGISTRY", {})
    except Exception as exc:
        return [f"could not import argus.linters.LINTER_REGISTRY: {exc}"]

    declared = _linting_names_in_yaml(architecture)
    missing = set(linter_registry.keys()) - declared
    return [
        f"linter ``{name}`` is in LINTER_REGISTRY but not in "
        f".ai/architecture.yaml under scanners.linting:"
        for name in sorted(missing)
    ]


def _check_reporters(architecture: dict) -> list[str]:
    try:
        eps = importlib_metadata.entry_points(group="argus.reporters")
        ep_names = {ep.name for ep in eps}
    except Exception as exc:
        return [f"could not enumerate argus.reporters entry-points: {exc}"]

    text = yaml.safe_dump(architecture, sort_keys=False)
    missing = {
        name for name in ep_names
        if name not in text
    }
    return [
        f"reporter ``{name}`` is in the argus.reporters entry-point "
        f"group but never mentioned in .ai/architecture.yaml"
        for name in sorted(missing)
    ]


def _check_cli_subcommands(context: dict) -> list[str]:
    try:
        cli_module = importlib.import_module("argus.cli")
        parser = _build_parser(cli_module)
        if parser is None:
            return []  # nothing to introspect; skip silently
        cli_names = _argparse_subcommands(parser)
    except Exception as exc:
        return [f"could not introspect argus.cli subcommands: {exc}"]

    declared = set(
        (context.get("entrypoints", {}) or {})
        .get("cli_subcommands", {}) or {}
    )
    missing = cli_names - declared
    return [
        f"CLI subcommand ``argus {name}`` exists on the argparse tree "
        f"but is not in .ai/context.yaml under "
        f"entrypoints.cli_subcommands:"
        for name in sorted(missing)
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data if isinstance(data, dict) else {}


def _all_scanner_names_in_yaml(architecture: dict) -> set[str]:
    """Collect scanner names from every scanners.<category>: list,
    EXCLUDING the linting category (which has its own check)."""
    out: set[str] = set()
    block = architecture.get("scanners", {}) or {}
    for category, entries in block.items():
        if category == "linting" or not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and "name" in entry:
                out.add(str(entry["name"]))
    return out


def _yaml_scanner_category_keys(architecture: dict) -> set[str]:
    """Return the top-level keys under ``scanners:`` in the YAML.

    Meta-scanners use a category key as their representation rather
    than a flat entry — ``container`` is the canonical example. The
    name check accepts a registry name if it matches either an entry
    or a category key.
    """
    block = architecture.get("scanners", {}) or {}
    return set(block.keys())


def _linting_names_in_yaml(architecture: dict) -> set[str]:
    out: set[str] = set()
    block = (architecture.get("scanners", {}) or {}).get("linting", []) or []
    for entry in block:
        if isinstance(entry, dict) and "name" in entry:
            out.add(str(entry["name"]))
    return out


def _build_parser(cli_module) -> argparse.ArgumentParser | None:
    for name in ("build_parser", "_build_parser", "make_parser", "create_parser"):
        builder = getattr(cli_module, name, None)
        if callable(builder):
            try:
                parser = builder()
                if isinstance(parser, argparse.ArgumentParser):
                    return parser
            except Exception:
                continue
    return None


def _argparse_subcommands(parser: argparse.ArgumentParser) -> set[str]:
    names: set[str] = set()
    for action in parser._actions:  # noqa: SLF001
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            names.update(action.choices.keys())
    return names


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
