"""View-model transformer for the Argus architecture map page.

This module is the **only** place that maps ``.ai/architecture.yaml``
(plus runtime SDK introspection) into the JSON shape that the
architecture page renders. Three consumers feed off the same
transformer output:

  - The MkDocs docsite build (writes
    ``architecture/index.html`` with the view model inlined as a
    ``<script type="application/json">`` block).
  - The ``argus view browser`` FastAPI app (renders the
    ``/architecture`` route from the same view model).
  - The ``argus mcp`` server (exposes the JSON at the
    ``argus://architecture`` resource for AI assistants).

No file in the repo is hand-authored from this shape — it is always
derived from canonical ``.ai/*.yaml`` plus live introspection of the
running SDK. Adding a scanner to ``.ai/architecture.yaml`` (and to
``argus/scanners/``) makes it appear on all three surfaces with no
other edits; the CI source-of-truth check enforces the registry-side
half of that contract.

Public surface (the only names anything outside this module should
import):

    SCHEMA_VERSION              - bumped when the view-model shape
                                  breaks; consumers can branch on it.
    Registries                  - dataclass bundling the runtime
                                  introspection inputs to
                                  ``build_view_model``. Construct via
                                  ``introspect_registries()``.
    introspect_registries()     - imports the running SDK and
                                  collects SCANNER_REGISTRY,
                                  LINTER_REGISTRY, the
                                  ``argus.reporters`` entry-point
                                  group, and the CLI subcommand list.
    load_inputs(repo_root)      - reads the four canonical files
                                  (architecture.yaml, decisions.yaml,
                                  argus-config.schema.json,
                                  version.yaml) into dicts.
    build_view_model(...)       - the deterministic pure transformer.
                                  Same inputs ⇒ byte-identical JSON.
"""

from __future__ import annotations

import argparse
import importlib
import json
from dataclasses import dataclass
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

import yaml


# Bumped whenever the view-model shape changes in a backwards-
# incompatible way. The MCP resource embeds it so an AI client can
# tell whether its cached parser still applies.
SCHEMA_VERSION = "1.0"


# --------------------------------------------------------------------------
# Public dataclasses
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Registries:
    """Snapshot of the running SDK's pluggable registries.

    Captured at view-model build time so the diagram cannot drift from
    the actually-installed code. Two scanners with the same name (one
    in YAML, none in the registry) is the failure mode the CI source-
    of-truth check guards against.
    """

    scanners: tuple[str, ...]
    """Names of every scanner in ``argus.scanners.SCANNER_REGISTRY``."""

    linters: tuple[str, ...]
    """Names of every linter in ``argus.linters.LINTER_REGISTRY``.

    Linters auto-merge into ``SCANNER_REGISTRY`` at import time, but
    we keep the breakdown so the diagram can show them as a separate
    column section.
    """

    reporters: tuple[str, ...]
    """Names of every reporter in the ``argus.reporters`` entry-point group."""

    cli_subcommands: tuple[str, ...]
    """Names of every ``argus`` subcommand parsed from the argparse tree."""


# --------------------------------------------------------------------------
# Runtime introspection — touches the installed SDK
# --------------------------------------------------------------------------


def introspect_registries() -> Registries:
    """Snapshot the running SDK's registries.

    Imports ``argus`` modules lazily so this module stays importable
    in environments without the full SDK installed (e.g. a docsite
    build container with only pyyaml). Each input is independently
    guarded: a missing entry-point group should not block the
    architecture page on a config-schema lookup, etc.
    """
    scanner_names = _safe_registry("argus.scanners", "SCANNER_REGISTRY")
    linter_names = _safe_registry("argus.linters", "LINTER_REGISTRY")
    reporter_names = _safe_entry_points("argus.reporters")
    cli_subcommands = _safe_cli_subcommands()

    return Registries(
        scanners=tuple(sorted(scanner_names)),
        linters=tuple(sorted(linter_names)),
        reporters=tuple(sorted(reporter_names)),
        cli_subcommands=tuple(sorted(cli_subcommands)),
    )


def _safe_registry(module_name: str, attr: str) -> set[str]:
    try:
        module = importlib.import_module(module_name)
        registry = getattr(module, attr, {})
        return set(registry.keys()) if isinstance(registry, dict) else set()
    except Exception:  # pragma: no cover — defensive
        return set()


def _safe_entry_points(group: str) -> set[str]:
    try:
        eps = importlib_metadata.entry_points(group=group)
        return {ep.name for ep in eps}
    except Exception:  # pragma: no cover — defensive
        return set()


def _safe_cli_subcommands() -> set[str]:
    """Parse the argparse tree in ``argus.cli`` for subcommand names."""
    try:
        cli = importlib.import_module("argus.cli")
        parser = _build_argparse(cli)
        if parser is None:
            return set()
        return _argparse_subcommands(parser)
    except Exception:  # pragma: no cover — defensive
        return set()


def _build_argparse(cli_module: Any) -> argparse.ArgumentParser | None:
    """Find the top-level ``argparse.ArgumentParser`` for the ``argus`` CLI."""
    for name in ("build_parser", "_build_parser", "make_parser", "create_parser"):
        builder = getattr(cli_module, name, None)
        if callable(builder):
            try:
                parser = builder()
                if isinstance(parser, argparse.ArgumentParser):
                    return parser
            except Exception:  # pragma: no cover
                continue
    return None


def _argparse_subcommands(parser: argparse.ArgumentParser) -> set[str]:
    """Walk a parser's subparsers and return their command names."""
    names: set[str] = set()
    for action in parser._actions:  # noqa: SLF001 — argparse exposes no public API
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            names.update(action.choices.keys())
    return names


# --------------------------------------------------------------------------
# File-side input loading
# --------------------------------------------------------------------------


def load_inputs(repo_root: Path) -> dict[str, Any]:
    """Read the four canonical input files into dicts.

    Returns a dict with keys ``architecture``, ``decisions``,
    ``config_schema``, ``version``, ``context``. Callers pass this
    plus a ``Registries`` instance into ``build_view_model``.
    """
    return {
        "architecture": _load_yaml(repo_root / ".ai" / "architecture.yaml"),
        "decisions": _load_yaml(repo_root / ".ai" / "decisions.yaml"),
        "context": _load_yaml(repo_root / ".ai" / "context.yaml"),
        "config_schema": _load_json(repo_root / "argus-config.schema.json"),
        "version": _load_version_yaml(repo_root / "version.yaml"),
    }


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data if isinstance(data, dict) else {}


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh) or {}
    return data if isinstance(data, dict) else {}


def _load_version_yaml(path: Path) -> str:
    """Read ``version.yaml`` and return the SDK version string.

    The file is either a YAML map with a ``version:`` key or a bare
    string like ``0.7.2 # x-release-it-version``. Both shapes ship in
    the wild — handle both rather than break the page on a release-it
    template tweak.
    """
    if not path.exists():
        return "0.0.0"
    text = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return "0.0.0"
    if isinstance(data, dict):
        return str(data.get("version", "0.0.0"))
    return str(data).strip() if data else "0.0.0"


# --------------------------------------------------------------------------
# The transformer — pure function from canonical inputs to view model
# --------------------------------------------------------------------------


# Stable column declarations. Order matters — left-to-right in the page.
# IDs are kebab-case ASCII to keep query-string round-trips clean.
COLUMNS: tuple[dict[str, str], ...] = (
    {"id": "actors",     "label": "Actors",     "swatch": "muted"},
    {"id": "surfaces",   "label": "Surfaces",   "swatch": "primary"},
    {"id": "core",       "label": "SDK core",   "swatch": "subtle"},
    {"id": "scanners",   "label": "Scanners & linters", "swatch": "accent"},
    {"id": "reporters",  "label": "Reporters",  "swatch": "primary"},
    {"id": "artifacts",  "label": "Artifacts",  "swatch": "info"},
    {"id": "consumers",  "label": "Consumers",  "swatch": "muted"},
)


# The flows from the prompt's "Flows on the right" section. Each path
# is a list of node IDs that must exist in the rendered graph. Edges
# implied between consecutive IDs in the path are highlighted when the
# flow is active. ADR overlays sit on flows of kind ``overlay``.
_FLOW_DEFS: tuple[dict[str, Any], ...] = (
    {
        "id": "flow-scan-source",
        "label": "argus scan (source)",
        "kind": "primary",
        "summary": "config → engine → scanners → findings → reporters → artifacts",
        "path": [
            "actor:developer", "surface:cli", "surface:scan",
            "core:engine", "scanner:bandit", "core:engine",
            "reporter:json", "artifact:results-json", "consumer:view-browser",
        ],
    },
    {
        "id": "flow-scan-container",
        "label": "argus scan container",
        "kind": "primary",
        "summary": "discovery → ContainerEngine → 5 sub-scanners → reporters",
        "path": [
            "actor:developer", "surface:cli", "surface:scan-container",
            "core:container-engine", "scanner:trivy", "scanner:grype",
            "scanner:syft", "scanner:exposure", "scanner:services",
            "core:engine", "reporter:json", "artifact:results-json",
        ],
    },
    {
        "id": "flow-init",
        "label": "argus init",
        "kind": "primary",
        "summary": "Auto-detect project → tailored argus.yml",
        "path": [
            "actor:developer", "surface:cli", "surface:init",
            "core:engine", "artifact:argus-yml",
        ],
    },
    {
        "id": "flow-validate",
        "label": "argus validate",
        "kind": "primary",
        "summary": "schema.py → ConfigError[]",
        "path": [
            "actor:developer", "surface:cli", "surface:validate",
            "core:schema",
        ],
    },
    {
        "id": "flow-view",
        "label": "argus view (terminal / browser)",
        "kind": "primary",
        "summary": "Load argus-results.json → findings_view → TUI or web UI",
        "path": [
            "actor:developer", "surface:cli", "surface:view",
            "artifact:results-json", "core:findings-view",
            "consumer:view-terminal", "consumer:view-browser",
        ],
    },
    {
        "id": "flow-report",
        "label": "argus report",
        "kind": "primary",
        "summary": "Re-emit canonical results without re-scanning",
        "path": [
            "actor:developer", "surface:cli", "surface:report",
            "artifact:results-json", "reporter:sarif",
            "artifact:sarif",
        ],
    },
    {
        "id": "flow-mcp",
        "label": "argus mcp",
        "kind": "primary",
        "summary": "stdio → tools dispatch → SDK entry points → resources",
        "path": [
            "actor:ai-assistant", "surface:mcp", "core:engine",
            "artifact:results-json", "consumer:mcp",
        ],
    },
    {
        "id": "flow-completion",
        "label": "argus completion",
        "kind": "primary",
        "summary": "Dynamic shell completion from SCANNER_REGISTRY",
        "path": [
            "actor:developer", "surface:cli", "surface:completion",
            "core:registry",
        ],
    },
    {
        "id": "flow-cache",
        "label": "argus cache",
        "kind": "primary",
        "summary": "DB cache volume management",
        "path": [
            "actor:developer", "surface:cli", "surface:cache",
        ],
    },
    {
        "id": "flow-composite",
        "label": "GitHub Actions composite action",
        "kind": "primary",
        "summary": "Workflow step → pip install argus-security → argus scan {scanner} → SARIF + PR comment",
        "path": [
            "actor:ci", "surface:composite-actions", "surface:cli",
            "core:engine", "reporter:sarif", "artifact:sarif",
            "consumer:github-security", "consumer:pr-comments",
        ],
    },
    {
        "id": "flow-audit",
        "label": "Audit trail",
        "kind": "overlay",
        "summary": "Every scan emits argus.log JSONL + argus-audit.json; mask_secrets runs at write time",
        "path": [
            "core:engine", "core:audit", "artifact:log-jsonl",
            "artifact:audit-json",
        ],
    },
    {
        "id": "flow-image-verify",
        "label": "Image verification",
        "kind": "overlay",
        "summary": "Pull → image_verify → cosign keyless verify for argus-owned images; digest-pin check for third-party",
        "path": [
            "core:engine", "core:image-verify", "core:prewarm",
        ],
    },
)


# The seven primary ADRs the prompt asks us to surface as tooltips.
# IDs match the ``- id:`` entries in ``.ai/decisions.yaml``.
_PINNED_ADRS: tuple[str, ...] = (
    "ADR-013",  # SDK pivot
    "ADR-014",  # docker fallback
    "ADR-018",  # canonical artifact
    "ADR-020",  # linter template
    "ADR-022",  # redaction
    "ADR-023",  # reporter entry-points
    "ADR-024",  # secrets resolver
)


def build_view_model(  # noqa: PLR0913 — five canonical inputs is the contract
    architecture: dict[str, Any],
    decisions: dict[str, Any],
    context: dict[str, Any],
    config_schema: dict[str, Any],
    version: str,
    registries: Registries,
) -> dict[str, Any]:
    """Pure transformer: canonical inputs → render-friendly JSON.

    Deterministic and side-effect-free. Same inputs ⇒ byte-identical
    output (modulo dict iteration order, which we control by sorting
    every list). The MCP resource, the FastAPI route, and the docsite
    build all call this identical function so the three surfaces can
    never diverge on what the architecture map says.

    Returns a dict with the following keys:

      schema_version  Bumped on shape-breaking changes (str).
      version         The SDK release this map describes (str).
      columns         List of {id, label, swatch}, left-to-right.
      nodes           List of {id, column, label, kind, file_paths,
                      purpose, adr_refs, scanner_config?, reporter?,
                      external_tool?} — every box on the diagram.
      edges           List of {from, to, kind, adr_refs} — every line
                      between boxes.
      flows           List of {id, label, summary, kind, path} — the
                      right-rail flow list.
      adrs            Lookup of pinned ADR id → {title, summary, status}.
      external_tools  Side-rail list of {id, name, purpose,
                      used_by[scanner_ids], adr_refs} — trivy, grype,
                      etc.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    # Build column-by-column so order on the page is stable and the
    # node-ID conventions stay readable. Each ``_build_*`` helper
    # appends to ``nodes`` and ``edges`` and may push fresh entries.
    _build_actor_nodes(nodes)
    _build_surface_nodes(nodes, registries, context)
    _build_core_nodes(nodes, architecture)
    _build_scanner_nodes(nodes, architecture, config_schema)
    _build_reporter_nodes(nodes, registries)
    _build_artifact_nodes(nodes)
    _build_consumer_nodes(nodes)

    external_tools = _build_external_tools(architecture)

    _build_edges(edges, nodes, external_tools)

    flows = _resolve_flows(_FLOW_DEFS, {n["id"] for n in nodes})

    adrs = _build_adr_index(decisions, _PINNED_ADRS)

    return {
        "schema_version": SCHEMA_VERSION,
        "version": version,
        "columns": list(COLUMNS),
        "nodes": sorted(nodes, key=lambda n: (n["column"], n["label"])),
        "edges": sorted(edges, key=lambda e: (e["from"], e["to"], e["kind"])),
        "flows": flows,
        "adrs": adrs,
        "external_tools": external_tools,
    }


# --------------------------------------------------------------------------
# Node builders — one per column
# --------------------------------------------------------------------------


def _build_actor_nodes(nodes: list[dict[str, Any]]) -> None:
    nodes.extend([
        {
            "id": "actor:developer",
            "column": "actors",
            "label": "Developer",
            "kind": "actor",
            "purpose": (
                "Runs ``argus scan`` on a laptop or in a feature-branch "
                "CI job; reads results in the TUI or browser viewer."
            ),
            "file_paths": [],
            "adr_refs": [],
        },
        {
            "id": "actor:ci",
            "column": "actors",
            "label": "CI workflow",
            "kind": "actor",
            "purpose": (
                "GitHub Actions / GitLab CI / Jenkins job invoking "
                "argus via the SDK or a composite action; uploads "
                "SARIF to the security tab and posts PR comments."
            ),
            "file_paths": [".github/actions/", "examples/workflows/"],
            "adr_refs": ["ADR-013"],
        },
        {
            "id": "actor:ai-assistant",
            "column": "actors",
            "label": "AI assistant",
            "kind": "actor",
            "purpose": (
                "Claude Desktop / Cursor / Cline connecting to the "
                "argus MCP server over stdio to invoke scans and read "
                "canonical results."
            ),
            "file_paths": ["argus/mcp.py"],
            "adr_refs": [],
        },
    ])


def _build_surface_nodes(
    nodes: list[dict[str, Any]],
    registries: Registries,
    context: dict[str, Any],
) -> None:
    """Build the surface column from the CLI subcommand list.

    Prefers runtime introspection (``argparse`` walk) over the YAML
    description in ``.ai/context.yaml``, and falls back when the
    runtime list is empty (e.g. the docsite build runs without the
    full SDK importable).
    """
    cli_names = list(registries.cli_subcommands)
    if not cli_names:
        # YAML-side fallback: keys under entrypoints.cli_subcommands.
        cli_names = list(
            (context.get("entrypoints", {}) or {}).get("cli_subcommands", {}) or {}
        )

    # Always emit the umbrella ``cli`` node so the diagram has an
    # anchor between actors and the subcommand nodes.
    nodes.append({
        "id": "surface:cli",
        "column": "surfaces",
        "label": "argus CLI",
        "kind": "surface",
        "purpose": "argparse entry point. Top-level dispatcher.",
        "file_paths": ["argus/cli.py", "argus/__main__.py"],
        "adr_refs": [],
    })

    for name in sorted(set(cli_names)):
        nodes.append({
            "id": f"surface:{name}",
            "column": "surfaces",
            "label": f"argus {name}",
            "kind": "surface-subcommand",
            "purpose": _cli_subcommand_purpose(context, name),
            "file_paths": ["argus/cli.py"],
            "adr_refs": [],
        })

    # Non-CLI surfaces: MCP server, viewers, composite-action layer.
    nodes.extend([
        {
            "id": "surface:mcp",
            "column": "surfaces",
            "label": "MCP stdio server",
            "kind": "surface",
            "purpose": (
                "Bundled argus mcp implements the Model Context "
                "Protocol over stdio. Exposes tools (scan, validate, "
                "classify) and resources (argus://config, "
                "argus://results/latest, argus://architecture)."
            ),
            "file_paths": ["argus/mcp.py"],
            "adr_refs": [],
        },
        {
            "id": "surface:view-terminal",
            "column": "surfaces",
            "label": "argus view terminal",
            "kind": "surface",
            "purpose": (
                "Textual TUI ([terminal] extra). Click-through and "
                "filter the canonical argus-results.json. Mouse-first "
                "interactivity in 8.x."
            ),
            "file_paths": ["argus/viewers/terminal/"],
            "adr_refs": [],
        },
        {
            "id": "surface:view-browser",
            "column": "surfaces",
            "label": "argus view browser",
            "kind": "surface",
            "purpose": (
                "FastAPI + Jinja2 read-only viewer ([browser] extra). "
                "Bound to 127.0.0.1; same canonical JSON as the TUI."
            ),
            "file_paths": ["argus/viewers/browser/"],
            "adr_refs": [],
        },
        {
            "id": "surface:composite-actions",
            "column": "surfaces",
            "label": "Composite actions",
            "kind": "surface",
            "purpose": (
                "Thin GitHub Actions wrappers per scanner. Pip-install "
                "argus-security, run argus scan, upload SARIF, post PR "
                "comment. No SDK code lives here — pure orchestration "
                "per ADR-013."
            ),
            "file_paths": [".github/actions/"],
            "adr_refs": ["ADR-013"],
        },
    ])


def _cli_subcommand_purpose(context: dict[str, Any], name: str) -> str:
    entrypoints = context.get("entrypoints", {}) or {}
    # v1: entrypoints.cli_subcommands is a {name: description} map.
    # AICaC v2.0 flattens entrypoints to a string→string map with each
    # subcommand keyed as ``cli_<name>``. Try both before the generic
    # fallback so the architecture map keeps the rich CLI descriptions.
    descs = entrypoints.get("cli_subcommands", {}) or {}
    return str(
        descs.get(name)
        or entrypoints.get(f"cli_{name}")
        or f"argus {name} subcommand"
    )


def _build_core_nodes(
    nodes: list[dict[str, Any]], architecture: dict[str, Any],
) -> None:
    """SDK core column. File-path-anchored components from architecture.yaml."""
    # Find the argus-sdk component to inherit its file paths + purpose
    # text.
    argus_sdk = _find_component(architecture, "argus-sdk")
    structure = (argus_sdk or {}).get("structure", {}) or {}

    core_specs: tuple[tuple[str, str, str, list[str]], ...] = (
        ("core:engine",          "ArgusEngine",         "core/engine.py", []),
        ("core:container-engine","ContainerEngine",     "container/engine.py", []),
        ("core:registry",        "SCANNER_REGISTRY",    "scanners/__init__.py", ["ADR-020"]),
        ("core:schema",          "Schema validator",    "core/schema.py", []),
        ("core:secrets",         "Secrets resolver",    "core/secrets.py", ["ADR-024"]),
        ("core:image-verify",    "Image verify",        "core/image_verify.py", []),
        ("core:redact",          "Redact",              "core/redact.py", ["ADR-022"]),
        ("core:prewarm",         "Image pre-warm",      "core/prewarm.py", ["ADR-014"]),
        ("core:audit",           "Audit logger + manifest", "audit/", []),
        ("core:findings-view",   "findings_view",       "core/findings_view.py", []),
    )
    for node_id, label, sub_path, adrs in core_specs:
        purpose = (
            structure.get(sub_path)
            or _structure_match_prefix(structure, sub_path)
            or f"{label} component."
        )
        file_path = f"argus/{sub_path}"
        nodes.append({
            "id": node_id,
            "column": "core",
            "label": label,
            "kind": "core",
            "purpose": str(purpose),
            "file_paths": [file_path],
            "adr_refs": list(adrs),
        })


def _build_scanner_nodes(
    nodes: list[dict[str, Any]],
    architecture: dict[str, Any],
    config_schema: dict[str, Any],
) -> None:
    """Build a node per scanner under ``scanners:`` in architecture.yaml.

    The ``container`` scanner is one box at this level — the five
    sub-scanners (trivy, grype, syft, exposure, services) get nodes
    of kind ``scanner-sub`` so the page can expand the container box
    inline.
    """
    scanners_block = architecture.get("scanners", {}) or {}
    for category, items in scanners_block.items():
        if category == "linting":  # handled separately below
            continue
        if not isinstance(items, list):
            continue
        for entry in items:
            if not isinstance(entry, dict) or "name" not in entry:
                continue
            name = str(entry["name"])
            # Container sub-scanners get a kind-tag for client-side
            # collapsing under the parent container box.
            kind = "scanner-sub" if category == "container" else "scanner"
            nodes.append({
                "id": f"scanner:{name}",
                "column": "scanners",
                "label": name,
                "kind": kind,
                "scanner_category": category,
                "purpose": str(entry.get("purpose", "")),
                "languages": entry.get("languages", []),
                "output_format": entry.get("output", ""),
                "scanner_config": _scanner_config_snippet(name, config_schema),
                "cli_invocation": f"argus scan {name}",
                "file_paths": [f"argus/scanners/{_filename_for_scanner(name)}.py"],
                "adr_refs": ["ADR-014"],  # local-or-container fallback
            })

    # Linters (auto-merged into SCANNER_REGISTRY but kept in their own
    # block in the YAML so they're visually distinct).
    linting_block = scanners_block.get("linting", []) or []
    for entry in linting_block:
        if not isinstance(entry, dict) or "name" not in entry:
            continue
        name = str(entry["name"])
        nodes.append({
            "id": f"linter:{name}",
            "column": "scanners",
            "label": name,
            "kind": "linter",
            "purpose": str(entry.get("purpose", "")),
            "output_format": entry.get("output", ""),
            "scanner_config": _scanner_config_snippet(name, config_schema),
            "cli_invocation": f"argus scan {name}",
            "file_paths": [
                f"argus/linters/{_filename_for_linter(name)}.py",
            ],
            "adr_refs": ["ADR-020", "ADR-014"],
        })


def _filename_for_scanner(name: str) -> str:
    """Map scanner name → file stem under ``argus/scanners/``."""
    # Argus scanners live as ``argus/scanners/<name>.py`` with hyphens
    # replaced by underscores. The few odd ones (``trivy-iac`` →
    # ``trivy_iac``, ``supply-chain`` → ``supply_chain``,
    # ``dependency-review`` → composite-only) get caught here.
    return name.replace("-", "_")


def _filename_for_linter(name: str) -> str:
    """Map linter name → file stem under ``argus/linters/``.

    Argus linter names are ``lint-<tool>``; the files drop the prefix.
    """
    return name.removeprefix("lint-").replace("-", "_")


def _scanner_config_snippet(
    name: str, config_schema: dict[str, Any],
) -> dict[str, Any]:
    """Build the per-scanner argus.yml snippet from the JSON Schema.

    Returns a dict with three keys: ``yaml`` (a YAML string with just
    this scanner under ``scanners:``), ``defaults`` (the validated
    default for each input from the sub-schema), and ``inputs`` (a
    list of ``{name, type, default, description}`` for the side-panel
    inputs renderer).
    """
    scanners = (
        (config_schema.get("properties", {}) or {}).get("scanners", {}) or {}
    )
    sub_schema = (scanners.get("properties", {}) or {}).get(name)
    inputs: list[dict[str, Any]] = []
    defaults: dict[str, Any] = {}
    if isinstance(sub_schema, dict):
        for key, val in (sub_schema.get("properties", {}) or {}).items():
            if not isinstance(val, dict):
                continue
            default = val.get("default")
            inputs.append({
                "name": key,
                "type": val.get("type", "string"),
                "default": default,
                "description": str(val.get("description", "")),
            })
            if default is not None:
                defaults[key] = default

    yaml_snippet = yaml.safe_dump(
        {"scanners": {name: {"enabled": True, **defaults}}},
        sort_keys=False, default_flow_style=False,
    )
    return {
        "yaml": yaml_snippet,
        "defaults": defaults,
        "inputs": sorted(inputs, key=lambda x: x["name"]),
    }


def _build_reporter_nodes(
    nodes: list[dict[str, Any]], registries: Registries,
) -> None:
    """Build a node per reporter discovered in the entry-point group.

    The ``json`` reporter is marked canonical per ADR-018 — that's the
    one that writes ``argus-results.json``, the single artifact every
    other consumer reads.
    """
    canonical = {"json"}
    for name in registries.reporters:
        nodes.append({
            "id": f"reporter:{name}",
            "column": "reporters",
            "label": name,
            "kind": "reporter",
            "is_canonical": name in canonical,
            "purpose": _reporter_purpose(name),
            "file_paths": [f"argus/reporters/{_filename_for_reporter(name)}.py"],
            "enable_via": (
                "reporting.formats: [..., '%s'] in argus.yml, "
                "or --format=%s on the CLI." % (name, name)
            ),
            "entry_point": f"argus.reporters / {name}",
            "adr_refs": ["ADR-023"],
        })


def _filename_for_reporter(name: str) -> str:
    """Reporter module names that don't match their entry-point name."""
    overrides = {"json": "json_report", "container_markdown": "container_markdown"}
    return overrides.get(name, name)


def _reporter_purpose(name: str) -> str:
    blurbs = {
        "terminal": "Rich-formatted console output for interactive runs.",
        "markdown": "Per-scanner Markdown summary, suitable for PR comments.",
        "sarif": "Static Analysis Results Interchange Format. Upload to GitHub / GitLab security tabs.",
        "json": "Canonical argus-results.json — the artifact every consumer reads (ADR-018).",
        "github": "GitHub Actions inline annotations (::error / ::warning).",
        "gitlab": "GitLab Code Quality JSON (codeclimate-compatible).",
        "junit": "JUnit XML for CI test dashboards.",
        "container_markdown": "Container-scan-specific Markdown layout.",
    }
    return blurbs.get(name, f"{name} reporter.")


def _build_artifact_nodes(nodes: list[dict[str, Any]]) -> None:
    artifacts: tuple[dict[str, Any], ...] = (
        {
            "id": "artifact:results-json",
            "label": "argus-results.json",
            "is_canonical": True,
            "purpose": (
                "Single canonical scan output. Always written by "
                "JsonReporter; every viewer, the MCP resource, and "
                "every external integration reads exactly this file "
                "(ADR-018)."
            ),
            "adr_refs": ["ADR-018"],
        },
        {
            "id": "artifact:log-jsonl",
            "label": "argus.log",
            "is_canonical": False,
            "purpose": (
                "Per-line JSON audit log emitted by argus.audit.logger. "
                "mask_secrets_in_obj runs at write time so credential-"
                "shaped strings can never leak into the trail."
            ),
            "adr_refs": ["ADR-022"],
        },
        {
            "id": "artifact:audit-json",
            "label": "argus-audit.json",
            "is_canonical": False,
            "purpose": (
                "Run summary manifest — start/end timestamps, scanner "
                "list, artifact hashes, error counts. Written by "
                "argus.audit.manifest.AuditManifest.save()."
            ),
            "adr_refs": ["ADR-022"],
        },
        {
            "id": "artifact:raw-dir",
            "label": "raw/",
            "is_canonical": False,
            "purpose": (
                "Per-scanner raw output preserved when "
                "reporting.keep_raw is true. Forensics + manual "
                "triage. One subdir per scanner."
            ),
            "adr_refs": [],
        },
        {
            "id": "artifact:sarif",
            "label": "SARIF files",
            "is_canonical": False,
            "purpose": (
                "Static Analysis Results Interchange Format files "
                "(one per SARIF-emitting scanner). Uploaded to GitHub "
                "/ GitLab security tabs by the composite-action flow."
            ),
            "adr_refs": [],
        },
        {
            "id": "artifact:argus-yml",
            "label": "argus.yml",
            "is_canonical": False,
            "purpose": (
                "User-authored or argus-init-generated configuration "
                "file. Drives which scanners run and their per-scanner "
                "inputs."
            ),
            "adr_refs": [],
        },
    )
    for spec in artifacts:
        nodes.append({
            **spec,
            "column": "artifacts",
            "kind": "artifact",
            "file_paths": [],
        })


def _build_consumer_nodes(nodes: list[dict[str, Any]]) -> None:
    consumers: tuple[dict[str, str], ...] = (
        {
            "id": "consumer:view-terminal",
            "label": "argus view terminal",
            "purpose": (
                "Textual TUI consumer of argus-results.json. Filter, "
                "search, export, dashboard, diff."
            ),
        },
        {
            "id": "consumer:view-browser",
            "label": "argus view browser",
            "purpose": (
                "FastAPI read-only viewer (127.0.0.1). Same canonical "
                "JSON, dashboard + findings + log + diff + picker + "
                "architecture routes."
            ),
        },
        {
            "id": "consumer:mcp",
            "label": "MCP resources",
            "purpose": (
                "AI assistants read argus://config, argus://results/"
                "latest, argus://architecture — all derived from the "
                "same canonical sources."
            ),
        },
        {
            "id": "consumer:github-security",
            "label": "GitHub Security tab",
            "purpose": (
                "SARIF upload landing zone. Surfaces findings on the "
                "repo Security tab and in PR Files Changed annotations."
            ),
        },
        {
            "id": "consumer:gitlab-security",
            "label": "GitLab security widgets",
            "purpose": (
                "GitLab Code Quality JSON consumer. Displays findings "
                "in MR widgets."
            ),
        },
        {
            "id": "consumer:junit-ci",
            "label": "JUnit-consuming CI dashboards",
            "purpose": (
                "CI providers (Jenkins, GitLab, CircleCI, ...) that "
                "consume JUnit XML for build-status reporting."
            ),
        },
        {
            "id": "consumer:pr-comments",
            "label": "Composite-action PR comments",
            "purpose": (
                "Inline PR comments posted by the comment-pr "
                "composite action with per-scanner severity counts "
                "and links to artifacts."
            ),
        },
    )
    for spec in consumers:
        nodes.append({
            **spec,
            "column": "consumers",
            "kind": "consumer",
            "file_paths": [],
            "adr_refs": [],
        })


def _build_external_tools(
    architecture: dict[str, Any],
) -> list[dict[str, Any]]:
    """Side-rail list of external tools (trivy, grype, etc.).

    Pulled from ``dependencies.external`` in architecture.yaml. Each
    entry includes ``used_by`` scanner IDs so the side-rail can light
    up edges into the scanner column.
    """
    deps = (architecture.get("dependencies", {}) or {}).get("external", {}) or {}
    # Heuristic mapping from external-tool name → scanner IDs that
    # consume it. The YAML doesn't model this directly; we infer from
    # the tool name vs. the scanner names.
    tools: list[dict[str, Any]] = []
    for tool_name, body in deps.items():
        if not isinstance(body, dict):
            continue
        used_by = _scanner_users_of(tool_name)
        tools.append({
            "id": f"tool:{tool_name}",
            "name": tool_name,
            "purpose": str(body.get("purpose", "")),
            "critical": bool(body.get("critical", False)),
            "used_by": used_by,
            "adr_refs": ["ADR-014"],  # local-or-container fallback
        })
    return sorted(tools, key=lambda t: t["name"])


def _scanner_users_of(tool: str) -> list[str]:
    """Map an external tool name → scanner node IDs that shell out to it."""
    # The YAML doesn't link tools ⇆ scanners explicitly, so we
    # encode the well-known relationships here. New scanner / tool
    # additions update this map. Any scanner not present just gets an
    # implicit "uses its own binary" — no edge in the diagram.
    mapping = {
        "trivy": ["scanner:trivy", "scanner:trivy-iac"],
        "grype": ["scanner:grype"],
        "syft": ["scanner:syft"],
        "gitleaks": ["scanner:gitleaks"],
        "codeql": ["scanner:codeql"],
        "osv-scanner": ["scanner:osv"],
        "dependency-review-action": ["scanner:dependency-review"],
    }
    return mapping.get(tool, [])


# --------------------------------------------------------------------------
# Edges between columns
# --------------------------------------------------------------------------


def _build_edges(
    edges: list[dict[str, Any]],
    nodes: list[dict[str, Any]],
    external_tools: list[dict[str, Any]],
) -> None:
    """Build the canonical edge set between columns.

    Edges are kept structural here (one column → next) so the diagram
    layout has predictable backbones to render. Flow-specific edges
    (which one is highlighted when a flow is active) come from the
    flow paths themselves and don't need to be enumerated here.
    """
    by_column = _group_by_column(nodes)

    # Actors → Surfaces. Each actor reaches the surfaces it owns:
    # developer → CLI, CI → composite-actions + CLI, AI → MCP.
    actor_targets = {
        "actor:developer": [
            "surface:cli", "surface:view-terminal", "surface:view-browser",
        ],
        "actor:ci": ["surface:composite-actions", "surface:cli"],
        "actor:ai-assistant": ["surface:mcp"],
    }
    for src, dsts in actor_targets.items():
        for dst in dsts:
            edges.append({"from": src, "to": dst, "kind": "invokes", "adr_refs": []})

    # CLI umbrella → each subcommand node. Visualizes the dispatcher.
    cli_subcommands = [
        n["id"] for n in by_column.get("surfaces", [])
        if n["kind"] == "surface-subcommand"
    ]
    for sub in cli_subcommands:
        edges.append({"from": "surface:cli", "to": sub, "kind": "dispatches", "adr_refs": []})

    # Subcommands → engine (most go through the engine; a few don't).
    direct_to_engine = {
        "surface:scan", "surface:scan-container", "surface:init",
        "surface:report", "surface:view", "surface:classify",
        "surface:collect",
    }
    for sub in cli_subcommands:
        if sub in direct_to_engine:
            target = (
                "core:container-engine" if sub == "surface:scan-container"
                else "core:engine"
            )
            edges.append({"from": sub, "to": target, "kind": "drives", "adr_refs": []})
    # ``validate`` drives the schema validator directly.
    if "surface:validate" in {n["id"] for n in by_column.get("surfaces", [])}:
        edges.append({
            "from": "surface:validate", "to": "core:schema",
            "kind": "drives", "adr_refs": [],
        })
    # ``completion`` reads the registry.
    if "surface:completion" in {n["id"] for n in by_column.get("surfaces", [])}:
        edges.append({
            "from": "surface:completion", "to": "core:registry",
            "kind": "reads", "adr_refs": [],
        })
    # ``mcp`` surface → engine for the scan/validate tool dispatch.
    edges.append({
        "from": "surface:mcp", "to": "core:engine", "kind": "dispatches", "adr_refs": [],
    })

    # Engine → every scanner / linter (registry-driven dispatch).
    scanner_ids = [
        n["id"] for n in by_column.get("scanners", [])
        if n["kind"] in ("scanner", "linter")
    ]
    for sid in scanner_ids:
        edges.append({
            "from": "core:engine", "to": sid, "kind": "dispatches",
            "adr_refs": ["ADR-020"] if sid.startswith("linter:") else [],
        })
    # Container engine drives the five container sub-scanners.
    sub_scanner_ids = [
        n["id"] for n in by_column.get("scanners", [])
        if n["kind"] == "scanner-sub"
    ]
    for sid in sub_scanner_ids:
        edges.append({
            "from": "core:container-engine", "to": sid,
            "kind": "dispatches", "adr_refs": [],
        })

    # External tools → scanner consumers. Side-rail edges with the
    # ADR-014 (local-or-container fallback) badge.
    for tool in external_tools:
        for sid in tool["used_by"]:
            edges.append({
                "from": tool["id"], "to": sid,
                "kind": "shells-out", "adr_refs": ["ADR-014"],
            })

    # Scanners → reporters (everything funnels through the engine's
    # ScanSummary, but the diagram is clearer with a direct lane).
    reporter_ids = [n["id"] for n in by_column.get("reporters", [])]
    for rid in reporter_ids:
        edges.append({
            "from": "core:engine", "to": rid,
            "kind": "emits", "adr_refs": ["ADR-023"],
        })

    # Reporters → artifacts.
    reporter_targets = {
        "reporter:json": ["artifact:results-json"],
        "reporter:sarif": ["artifact:sarif"],
        "reporter:terminal": [],  # terminal renders to stdout, no artifact
        "reporter:markdown": [],
        "reporter:github": [],
        "reporter:gitlab": [],
        "reporter:junit": [],
        "reporter:container_markdown": [],
    }
    for rid in reporter_ids:
        for art in reporter_targets.get(rid, []):
            edges.append({
                "from": rid, "to": art, "kind": "writes", "adr_refs": [],
            })

    # Audit module → log + audit-json artifacts.
    edges.append({
        "from": "core:audit", "to": "artifact:log-jsonl",
        "kind": "writes", "adr_refs": ["ADR-022"],
    })
    edges.append({
        "from": "core:audit", "to": "artifact:audit-json",
        "kind": "writes", "adr_refs": ["ADR-022"],
    })
    edges.append({
        "from": "core:engine", "to": "core:audit",
        "kind": "emits", "adr_refs": [],
    })
    edges.append({
        "from": "core:engine", "to": "artifact:raw-dir",
        "kind": "writes", "adr_refs": [],
    })

    # Image verification chain.
    edges.append({
        "from": "core:prewarm", "to": "core:image-verify",
        "kind": "calls", "adr_refs": [],
    })

    # Artifacts → consumers. ``argus-results.json`` is the bus.
    art_targets = {
        "artifact:results-json": [
            "consumer:view-terminal", "consumer:view-browser", "consumer:mcp",
        ],
        "artifact:sarif": [
            "consumer:github-security", "consumer:gitlab-security",
        ],
        "artifact:log-jsonl": [],
        "artifact:audit-json": [],
        "artifact:raw-dir": [],
        "artifact:argus-yml": [],
    }
    for art, dsts in art_targets.items():
        for dst in dsts:
            edges.append({
                "from": art, "to": dst, "kind": "read-by", "adr_refs": [],
            })


def _group_by_column(
    nodes: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for n in nodes:
        out.setdefault(n["column"], []).append(n)
    return out


# --------------------------------------------------------------------------
# Flows + ADR cross-reference
# --------------------------------------------------------------------------


def _resolve_flows(
    flow_defs: tuple[dict[str, Any], ...],
    known_node_ids: set[str],
) -> list[dict[str, Any]]:
    """Filter flow paths to only nodes that actually got rendered.

    A flow that references a node which didn't make it into the
    diagram (e.g. a CLI subcommand that's defined in the YAML but the
    introspection couldn't find at build time) would create a dangling
    highlight target. Drop unknown IDs from the path silently — the
    rest of the flow still highlights cleanly.
    """
    resolved: list[dict[str, Any]] = []
    for flow in flow_defs:
        path = [pid for pid in flow["path"] if pid in known_node_ids]
        resolved.append({
            "id": flow["id"],
            "label": flow["label"],
            "summary": flow["summary"],
            "kind": flow["kind"],
            "path": path,
            "steps": [
                {"node_id": pid, "index": i + 1}
                for i, pid in enumerate(path)
            ],
        })
    return resolved


def _build_adr_index(
    decisions: dict[str, Any], pinned_ids: tuple[str, ...],
) -> list[dict[str, Any]]:
    """Build a sorted ADR list filtered to the pinned IDs.

    ``.ai/decisions.yaml`` stores ADRs under top-level keys. The
    schema is permissive — try a few common shapes and skip anything
    that doesn't parse cleanly. Pinned IDs that don't resolve get a
    placeholder entry so the page can at least render a "see commit"
    tooltip rather than 404 on the link.
    """
    by_id: dict[str, dict[str, Any]] = {}
    # Two common ``decisions.yaml`` shapes: a flat list under
    # ``decisions:``, or a map keyed by ADR id. Handle both.
    bucket = decisions.get("decisions") or decisions.get("adrs") or []
    if isinstance(bucket, list):
        for entry in bucket:
            if not isinstance(entry, dict):
                continue
            entry_id = str(entry.get("id", "")).upper()
            if entry_id:
                by_id[entry_id] = entry
    elif isinstance(bucket, dict):
        for entry_id, body in bucket.items():
            if isinstance(body, dict):
                body_with_id = {"id": entry_id, **body}
                by_id[str(entry_id).upper()] = body_with_id

    out: list[dict[str, Any]] = []
    for adr_id in pinned_ids:
        entry = by_id.get(adr_id, {})
        out.append({
            "id": adr_id,
            "title": str(entry.get("title", adr_id)),
            "status": str(entry.get("status", "")),
            "summary": str(entry.get("summary", entry.get("decision", ""))),
            "found": adr_id in by_id,
        })
    return out


# --------------------------------------------------------------------------
# Helpers shared by node builders
# --------------------------------------------------------------------------


def _find_component(
    architecture: dict[str, Any], name: str,
) -> dict[str, Any] | None:
    """Locate a component by ``name`` under the top-level ``components``.

    AICaC v1 stores ``components`` as a list of ``{name: ..., ...}`` dicts;
    v2.0 stores it as a dict keyed by component name. Handle both so the
    SDK-core node purposes resolve from the component ``structure`` map
    instead of falling back to generic placeholders.
    """
    components = architecture.get("components")
    if isinstance(components, dict):  # v2: keyed by name
        entry = components.get(name)
        return entry if isinstance(entry, dict) else None
    for entry in components or []:    # v1: list of {name: ...}
        if isinstance(entry, dict) and entry.get("name") == name:
            return entry
    return None


def _structure_match_prefix(
    structure: dict[str, str], sub_path: str,
) -> str | None:
    """Some structure keys use trailing slashes (``audit/``) — handle that."""
    for key, val in structure.items():
        if key.rstrip("/") == sub_path.rstrip("/"):
            return val
    return None


# --------------------------------------------------------------------------
# Build-time entry: emit JSON for the docsite + sanity-check.
# --------------------------------------------------------------------------


def build_view_model_from_repo(repo_root: Path) -> dict[str, Any]:
    """Convenience wrapper: load + introspect + transform from a repo root.

    Used by the FastAPI route and the MCP resource. The docsite build
    uses ``load_inputs`` + ``build_view_model`` directly so it can
    inline the result without an extra round-trip.
    """
    inputs = load_inputs(repo_root)
    registries = introspect_registries()
    return build_view_model(
        architecture=inputs["architecture"],
        decisions=inputs["decisions"],
        context=inputs["context"],
        config_schema=inputs["config_schema"],
        version=inputs["version"],
        registries=registries,
    )


# --------------------------------------------------------------------------
# Standalone HTML rendering for the docsite build
# --------------------------------------------------------------------------


_ARCH_INLINE_BODY = """    <div class="arch-page" data-mode="view">
      <main class="arch-page__main">
        <div class="arch-toolbar">
          <h2 class="arch-toolbar__title">Argus SDK &mdash; architecture &amp; flows</h2>
          <button type="button" id="arch-configure-toggle"
                  class="arch-toolbar__btn" aria-pressed="false"
                  data-tooltip="Toggle multi-select mode: pick scanners across the columns and Argus generates a working argus.yml, CLI invocation, GitHub Actions workflow, or MCP client config from the selection.">
            Configure
          </button>
        </div>

        <div id="arch-drawer-backdrop" class="arch-drawer-backdrop"
             aria-hidden="true"></div>

        <div class="arch-columns-viewport" id="arch-columns-viewport">
          <button type="button" id="arch-info-toggle"
                  class="arch-info-toggle"
                  aria-expanded="false" aria-controls="arch-info-popover"
                  aria-label="About this diagram" title="About this diagram">
            <svg width="14" height="14" viewBox="0 0 16 16"
                 fill="none" stroke="currentColor" stroke-width="1.6"
                 stroke-linecap="round" stroke-linejoin="round"
                 aria-hidden="true" focusable="false">
              <circle cx="8" cy="8" r="6.25" />
              <path d="M8 7v4" />
              <circle cx="8" cy="4.75" r="0.4" fill="currentColor" stroke="none" />
            </svg>
          </button>

          <div id="arch-info-popover" class="arch-info-popover" hidden
               role="dialog" aria-label="About this diagram">
            Every component that powers <code>argus scan</code> &mdash; the CLI
            surfaces, the SDK core, every scanner / linter / reporter, the
            artifacts they produce, and the consumers that read them.
            Pick a flow from the <strong>Flows</strong> panel on the left
            to highlight a path through the columns and see the
            step-by-step walkthrough on the right. Click any node for
            source paths, related ADRs, and a copy-pasteable config
            snippet. Drag to pan, scroll or use the zoom controls to
            navigate. Toggle <strong>Configure</strong> to multi-select
            scanners and generate a working <code>argus.yml</code>, CLI
            invocation, GitHub Actions workflow, or MCP client config
            from the selection.
          </div>

          <section id="arch-columns" class="arch-columns"
                   aria-label="Architecture columns"></section>

          <div class="arch-zoom-controls" aria-label="Zoom controls">
            <button type="button" id="arch-zoom-fit"
                    class="arch-zoom-btn arch-zoom-fit"
                    aria-label="Reset view" title="Reset view"
                    data-tooltip="Fit the entire diagram in the viewport.">
              <svg width="14" height="14" viewBox="0 0 16 16"
                   fill="none" stroke="currentColor" stroke-width="1.6"
                   stroke-linecap="round" stroke-linejoin="round"
                   aria-hidden="true" focusable="false">
                <path d="M2 5V2h3M14 5V2h-3M2 11v3h3M14 11v3h-3" />
              </svg>
            </button>
            <button type="button" id="arch-zoom-out" class="arch-zoom-btn"
                    aria-label="Zoom out" title="Zoom out"
                    data-tooltip="Zoom out (or scroll wheel down on the diagram).">&minus;</button>
            <button type="button" id="arch-zoom-reset"
                    class="arch-zoom-btn arch-zoom-reset"
                    aria-label="Current zoom &mdash; click to reset" title="Reset zoom"
                    data-tooltip="Current zoom level. Click to reset to fit-to-view.">100%</button>
            <button type="button" id="arch-zoom-in" class="arch-zoom-btn"
                    aria-label="Zoom in" title="Zoom in"
                    data-tooltip="Zoom in (or scroll wheel up on the diagram).">+</button>
          </div>

          <button type="button" id="arch-help-toggle"
                  class="arch-help-toggle"
                  aria-label="Replay the help tour" title="Help"
                  data-tooltip="Replay the guided tour.">
            <svg width="14" height="14" viewBox="0 0 16 16"
                 fill="none" stroke="currentColor" stroke-width="1.6"
                 stroke-linecap="round" stroke-linejoin="round"
                 aria-hidden="true" focusable="false">
              <circle cx="8" cy="8" r="6.25" />
              <path d="M6 6a2 2 0 1 1 2.6 1.9c-.5.2-.6.5-.6 1V10" />
              <circle cx="8" cy="11.75" r="0.4" fill="currentColor" stroke="none" />
            </svg>
          </button>
        </div>

        <section id="arch-picker" class="arch-picker" hidden
                 aria-label="Configure mode output">
          <div class="arch-picker__controls">
            <label for="arch-sev">severity_threshold:</label>
            <select id="arch-sev" data-control="severity">
              <option value="none">none</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
            <label for="arch-fmt">format:</label>
            <select id="arch-fmt" data-control="format">
              <option value="terminal">terminal</option>
              <option value="markdown">markdown</option>
              <option value="sarif">sarif</option>
              <option value="json">json</option>
              <option value="github">github</option>
              <option value="gitlab">gitlab</option>
              <option value="junit">junit</option>
            </select>
          </div>
          <div class="arch-picker__tabs">
            <button type="button" class="arch-picker__tab"
                    data-tab="yaml" aria-selected="true">argus.yml</button>
            <button type="button" class="arch-picker__tab"
                    data-tab="cli" aria-selected="false">CLI</button>
            <button type="button" class="arch-picker__tab"
                    data-tab="github" aria-selected="false">GitHub Actions</button>
            <button type="button" class="arch-picker__tab"
                    data-tab="mcp" aria-selected="false">MCP client</button>
          </div>
          <div class="arch-picker__pane" data-pane="yaml" data-active="true"></div>
          <div class="arch-picker__pane" data-pane="cli"></div>
          <div class="arch-picker__pane" data-pane="github"></div>
          <div class="arch-picker__pane" data-pane="mcp"></div>
        </section>

        <aside class="arch-tools" aria-label="External tools">
          <h3 class="arch-tools__title"
              data-tooltip="Third-party command-line tools that the SDK scanners shell out to. Argus doesn't bundle them &mdash; you need them on PATH or supply a container image. Click any tool to see which scanners invoke it and where the fallback lives.">External tools</h3>
          <ul id="arch-tools-list" class="arch-tools__list"></ul>
        </aside>
      </main>

      <button type="button" id="arch-toggle-flows"
              class="arch-drawer-handle arch-drawer-handle--flows"
              aria-pressed="false" aria-label="Toggle flows panel"
              title="Flows">
        <svg width="14" height="14" viewBox="0 0 16 16"
             fill="none" stroke="currentColor" stroke-width="1.8"
             stroke-linecap="round" stroke-linejoin="round"
             aria-hidden="true" focusable="false">
          <path d="M5 3l5 5-5 5" />
        </svg>
      </button>

      <button type="button" id="arch-toggle-steps"
              class="arch-drawer-handle arch-drawer-handle--steps"
              aria-pressed="false" aria-label="Toggle steps panel"
              title="Steps">
        <svg width="14" height="14" viewBox="0 0 16 16"
             fill="none" stroke="currentColor" stroke-width="1.8"
             stroke-linecap="round" stroke-linejoin="round"
             aria-hidden="true" focusable="false">
          <path d="M11 3l-5 5 5 5" />
        </svg>
      </button>

      <aside class="arch-page__sidebar arch-page__sidebar--flows"
             aria-label="Flows">
        <h3 class="arch-flows__title">Flows</h3>
        <p class="arch-flow__summary">
          Pick a flow to highlight the path through the columns.
        </p>
        <ul id="arch-flows-list" class="arch-flows__list"></ul>
        <button type="button" id="arch-flow-clear" class="arch-flows__clear"
                data-tooltip="Remove the active flow highlight and return every column to its idle (un-dimmed) state.">
          Clear flow
        </button>
      </aside>

      <aside class="arch-page__sidebar arch-page__sidebar--steps"
             aria-label="Flow steps">
        <section id="arch-steps" class="arch-steps">
          <h3 class="arch-steps__title">Steps</h3>
          <ol id="arch-steps-list" class="arch-steps__list"></ol>
          <p class="arch-steps__empty">
            Pick a flow on the left to see the step-by-step path.
          </p>
        </section>
      </aside>

      <div id="arch-tour" class="arch-tour" hidden role="dialog"
           aria-label="Architecture viewer tour" aria-modal="true">
        <div class="arch-tour__dim arch-tour__dim--top"></div>
        <div class="arch-tour__dim arch-tour__dim--right"></div>
        <div class="arch-tour__dim arch-tour__dim--bottom"></div>
        <div class="arch-tour__dim arch-tour__dim--left"></div>
        <div id="arch-tour-bubble" class="arch-tour__bubble"
             data-placement="bottom">
          <button type="button" id="arch-tour-close"
                  class="arch-tour__close"
                  aria-label="Exit tour" title="Exit tour">
            <svg width="12" height="12" viewBox="0 0 16 16"
                 fill="none" stroke="currentColor" stroke-width="1.8"
                 stroke-linecap="round" aria-hidden="true" focusable="false">
              <path d="M3 3L13 13M13 3L3 13" />
            </svg>
          </button>
          <p class="arch-tour__step-count">
            <span id="arch-tour-step-current">1</span>
            of
            <span id="arch-tour-step-total">1</span>
          </p>
          <h3 class="arch-tour__title" id="arch-tour-title"></h3>
          <div class="arch-tour__body" id="arch-tour-body"></div>
          <div class="arch-tour__controls">
            <label class="arch-tour__dontshow">
              <input type="checkbox" id="arch-tour-dontshow" />
              Don't show again
            </label>
            <div class="arch-tour__nav">
              <button type="button" id="arch-tour-prev"
                      class="arch-tour__btn">Back</button>
              <button type="button" id="arch-tour-next"
                      class="arch-tour__btn arch-tour__btn--primary">Next</button>
            </div>
          </div>
        </div>
      </div>

      <aside id="arch-panel" class="arch-panel" aria-label="Node details">
        <button type="button" id="arch-panel-close" class="arch-panel__close"
                aria-label="Close" title="Close">
          <svg width="12" height="12" viewBox="0 0 16 16"
               fill="none" stroke="currentColor" stroke-width="1.8"
               stroke-linecap="round" aria-hidden="true" focusable="false">
            <path d="M3 3L13 13M13 3L3 13" />
          </svg>
        </button>
        <header class="arch-panel__header" id="arch-panel-header">
          <h3 class="arch-panel__label"></h3>
          <p class="arch-panel__kind"></p>
        </header>
        <div class="arch-panel__body-wrap">
          <div class="arch-panel__body"></div>
        </div>
      </aside>
    </div>
"""


def render_inline_markdown(
    view_model: dict[str, Any],
    docs_root: Path,
    static_source_dir: Path | None = None,
) -> Path:
    """Render the architecture page as a Markdown file inside MkDocs.

    Writes ``docs_root/architecture.md`` with the ``.arch-page``
    markup inlined inside Material's content area, and copies
    ``architecture.css`` + ``architecture.js`` to ``docs_root/assets/``
    so the page's stylesheet and behaviour are loaded alongside
    the rest of the docsite. The Argus design tokens come from the
    site-wide custom theme (``custom.css``), so the architecture page
    no longer ships its own ``argus.css`` — the docsite owns the
    palette for every page.

    Args:
        view_model: Output of ``build_view_model`` — JSON-serializable.
        docs_root: The ``docs/`` directory the MkDocs source tree
            lives in. We write ``architecture.md`` at its root and
            ``assets/architecture.{css,js}`` underneath.
        static_source_dir: Where to copy CSS/JS from. Defaults to
            ``argus/viewers/browser/static`` resolved via the argus
            package path.

    Returns:
        The path to the written ``architecture.md``.
    """
    import json
    import shutil
    import textwrap

    docs_root = Path(docs_root)
    assets_dir = docs_root / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)

    if static_source_dir is None:
        # Default: locate argus/viewers/browser/static via the
        # package's __init__.py path. Works for both editable and
        # wheel installs.
        import argus  # noqa: PLC0415 — defer import to runtime
        static_source_dir = (
            Path(argus.__file__).resolve().parent / "viewers" / "browser" / "static"
        )

    # Copy CSS / JS sideways. Fail silently for missing files — the
    # docsite build should be diagnostic, not fatal, when one of the
    # static assets is misplaced (the page will still load, just
    # without that asset).
    for name in ("architecture.css", "architecture.js"):
        src = static_source_dir / name
        if src.exists():
            shutil.copy2(src, assets_dir / name)

    # JSON-encode the view model and embed as the page's
    # ``arch-data`` script block. ``</script>`` substrings in any
    # field would otherwise break out of the script context — escape
    # them via a unicode-escape on the angle bracket.
    view_model_json = json.dumps(view_model).replace("</", "<\\/")

    md = (
        "---\n"
        "title: Architecture\n"
        "hide:\n"
        "  - navigation\n"
        "  - toc\n"
        "---\n"
        "\n"
        "<style>\n"
        "/* Escape Material's content max-width so the diagram has\n"
        "   the full viewport to work with. Material constrains via\n"
        "   ``.md-main__inner`` (the outer cap), ``.md-content``,\n"
        "   ``.md-content__inner`` and ``article`` — all four need\n"
        "   the cap dropped to let our fixed sidebars sit at the\n"
        "   viewport edges. */\n"
        ".md-main__inner { max-width: none; margin: 0; }\n"
        ".md-content { max-width: none; }\n"
        ".md-content__inner { padding: 0; margin: 0; max-width: none; }\n"
        ".md-content > article { max-width: none; padding: 0; }\n"
        ".md-content h1 { display: none; }\n"
        "\n"
        "/* The architecture page has fixed-position sidebars at\n"
        "   z-index 20 and a detail panel at z-index 30. Material's\n"
        "   sticky header defaults to z-index 4 so it slides under\n"
        "   them on scroll. Bump the header above the panel so it\n"
        "   stays the topmost piece of chrome below the tour overlay\n"
        "   (which lives at z-index 1000). */\n"
        ".md-header { z-index: 100; }\n"
        "\n"
        "/* Material's ``.md-typeset`` paragraph and list rules outrun\n"
        "   architecture.css on specificity (``.md-typeset ul`` is\n"
        "   (0,1,1) vs our ``.arch-flows__list`` at (0,1,0)). Reset\n"
        "   the structural defaults inside ``.arch-page`` so our\n"
        "   custom layout actually wins. */\n"
        ".md-typeset .arch-page ul,\n"
        ".md-typeset .arch-page ol {\n"
        "  list-style: none; padding: 0; margin: 0;\n"
        "}\n"
        ".md-typeset .arch-page li { margin: 0; }\n"
        ".md-typeset .arch-page p { margin: 0; }\n"
        ".md-typeset .arch-page h2,\n"
        ".md-typeset .arch-page h3,\n"
        ".md-typeset .arch-page h4 { margin: 0; font-weight: inherit; }\n"
        ".md-typeset .arch-page code { font-size: inherit; padding: 0; "
        "background: transparent; border-radius: 0; }\n"
        "</style>\n"
        "\n"
        '<link rel="stylesheet" href="../assets/architecture.css" />\n'
        "\n"
        # Dedent the body — Markdown treats any line indented by four
        # spaces as a code block, so the standalone template's
        # ``    <div class="arch-page">…`` would otherwise render as a
        # giant ``<pre>`` block instead of as raw HTML.
        + textwrap.dedent(_ARCH_INLINE_BODY) +
        "\n"
        '<script id="arch-data" type="application/json">'
        f"{view_model_json}</script>\n"
        '<script src="../assets/architecture.js" defer></script>\n'
    )
    out = docs_root / "architecture.md"
    out.write_text(md, encoding="utf-8")
    return out
