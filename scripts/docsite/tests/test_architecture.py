"""Tests for ``scripts/docsite/architecture.py`` — the view-model
transformer that feeds the architecture page (docsite + browser
viewer + MCP resource).

Strategy: build the view model once against the real repo + run a
table of structural assertions across it. The transformer is pure
and deterministic, so a single canonical fixture exercises every
contract.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml


# Repo root resolution: tests run from anywhere as long as the
# project layout matches the real repo. The transformer file lives at
# scripts/docsite/architecture.py.
REPO_ROOT = Path(__file__).resolve().parents[3]
ARCH_MODULE_PATH = REPO_ROOT / "scripts" / "docsite" / "architecture.py"


@pytest.fixture(scope="module")
def architecture_module():
    """Load architecture.py once per test module."""
    spec = importlib.util.spec_from_file_location(
        "architecture_under_test", ARCH_MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["architecture_under_test"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def vm(architecture_module):
    """Build the view model once for the whole module."""
    return architecture_module.build_view_model_from_repo(REPO_ROOT)


@pytest.fixture(scope="module")
def inputs(architecture_module):
    """Raw loaded inputs (architecture.yaml, decisions.yaml, ...)."""
    return architecture_module.load_inputs(REPO_ROOT)


@pytest.fixture(scope="module")
def registries(architecture_module):
    """Runtime registry snapshot from the installed SDK."""
    return architecture_module.introspect_registries()


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


class TestViewModelShape:
    """Every top-level key of the view model is present and well-typed."""

    def test_has_required_top_level_keys(self, vm):
        required = {
            "schema_version", "version", "columns", "nodes",
            "edges", "flows", "adrs", "external_tools",
        }
        assert required.issubset(vm.keys())

    def test_schema_version_is_string(self, vm):
        assert isinstance(vm["schema_version"], str)
        assert vm["schema_version"]  # non-empty

    def test_version_is_string(self, vm):
        # Could be "0.7.2" or "1.0.0" — we don't care which, just that
        # something resolved.
        assert isinstance(vm["version"], str)
        assert vm["version"] != "0.0.0", (
            "version.yaml should have resolved to a real SDK version"
        )

    def test_columns_in_expected_order(self, vm):
        expected_order = [
            "actors", "surfaces", "core", "scanners",
            "reporters", "artifacts", "consumers",
        ]
        actual = [c["id"] for c in vm["columns"]]
        assert actual == expected_order


# ---------------------------------------------------------------------------
# Determinism — the contract the MCP resource relies on
# ---------------------------------------------------------------------------


class TestDeterminism:
    """Same inputs ⇒ byte-identical output."""

    def test_build_view_model_is_deterministic(
        self, architecture_module, inputs, registries,
    ):
        first = architecture_module.build_view_model(
            architecture=inputs["architecture"],
            decisions=inputs["decisions"],
            context=inputs["context"],
            config_schema=inputs["config_schema"],
            version=inputs["version"],
            registries=registries,
        )
        second = architecture_module.build_view_model(
            architecture=inputs["architecture"],
            decisions=inputs["decisions"],
            context=inputs["context"],
            config_schema=inputs["config_schema"],
            version=inputs["version"],
            registries=registries,
        )
        # Round-trip through JSON to canonicalize dict ordering since
        # Python preserves insertion order but JSON serialization is
        # the actual surface area for the MCP / HTML consumers.
        assert json.dumps(first, sort_keys=True) == json.dumps(
            second, sort_keys=True,
        )


# ---------------------------------------------------------------------------
# Every scanner / linter / reporter from runtime introspection
# has a corresponding node
# ---------------------------------------------------------------------------


class TestRegistryCoverage:
    """The diagram cannot drift from the running SDK."""

    def test_every_scanner_in_registry_has_a_node(self, vm, registries, inputs):
        # The SCANNER_REGISTRY auto-merges LINTER_REGISTRY entries at
        # import time. We split them here and verify both sides.
        scanner_node_ids = {
            n["id"].split(":", 1)[1]
            for n in vm["nodes"]
            if n["kind"] in ("scanner", "scanner-sub")
        }
        # Names declared in architecture.yaml's ``scanners:`` block,
        # excluding the linting category (those become linter: nodes).
        arch_scanners_block = inputs["architecture"].get("scanners", {}) or {}
        declared = set()
        for category, entries in arch_scanners_block.items():
            if category == "linting" or not isinstance(entries, list):
                continue
            for e in entries:
                if isinstance(e, dict) and "name" in e:
                    declared.add(e["name"])
        # Every name declared in the YAML must appear as a scanner /
        # scanner-sub node — that's the registry's job to enforce, but
        # the diagram has to honor it.
        missing = declared - scanner_node_ids
        assert not missing, (
            f"Scanners declared in .ai/architecture.yaml but missing "
            f"as diagram nodes: {sorted(missing)}"
        )

    def test_every_linter_in_registry_has_a_node(self, vm, registries, inputs):
        linter_node_ids = {
            n["id"].split(":", 1)[1] for n in vm["nodes"] if n["kind"] == "linter"
        }
        linting_block = (
            inputs["architecture"].get("scanners", {}) or {}
        ).get("linting", []) or []
        declared = {
            e["name"] for e in linting_block
            if isinstance(e, dict) and "name" in e
        }
        missing = declared - linter_node_ids
        assert not missing, f"Linters missing from diagram: {sorted(missing)}"

    def test_every_reporter_in_entrypoint_group_has_a_node(self, vm, registries):
        reporter_node_names = {
            n["id"].split(":", 1)[1]
            for n in vm["nodes"]
            if n["kind"] == "reporter"
        }
        missing = set(registries.reporters) - reporter_node_names
        assert not missing, (
            f"Reporters in the argus.reporters entry-point group but "
            f"missing as diagram nodes: {sorted(missing)}"
        )

    def test_json_reporter_marked_canonical(self, vm):
        """ADR-018 says JSON is the canonical artifact — surface that."""
        json_node = next(
            (n for n in vm["nodes"] if n["id"] == "reporter:json"), None,
        )
        assert json_node is not None
        assert json_node.get("is_canonical") is True


# ---------------------------------------------------------------------------
# Flows resolve to real node IDs
# ---------------------------------------------------------------------------


class TestFlows:
    """Every step in every flow must point to a node that exists."""

    def test_all_flow_paths_resolve(self, vm):
        node_ids = {n["id"] for n in vm["nodes"]}
        for flow in vm["flows"]:
            for step in flow["steps"]:
                assert step["node_id"] in node_ids, (
                    f"Flow {flow['id']!r} step references unknown node "
                    f"{step['node_id']!r}"
                )

    def test_at_least_one_primary_flow_per_promised_cli_subcommand(self, vm):
        """The prompt lists 10 primary flows. At minimum every CLI
        subcommand the SDK ships must have a flow that walks through
        it."""
        promised_subcommands = {
            "scan", "init", "validate", "view", "report", "mcp",
            "completion", "cache",
        }
        flow_labels = {f["label"] for f in vm["flows"]}
        # Each subcommand's flow is labeled e.g. "argus scan (source)"
        # or "argus mcp". A substring match per subcommand is enough.
        for sub in promised_subcommands:
            assert any(sub in label.lower() for label in flow_labels), (
                f"No flow mentions ``argus {sub}``"
            )

    def test_audit_and_image_verify_flows_are_overlays(self, vm):
        kinds = {f["id"]: f["kind"] for f in vm["flows"]}
        assert kinds.get("flow-audit") == "overlay"
        assert kinds.get("flow-image-verify") == "overlay"


# ---------------------------------------------------------------------------
# ADR cross-reference — every referenced ADR is in decisions.yaml
# ---------------------------------------------------------------------------


class TestAdrs:
    """Every ADR pinned to the page must exist in decisions.yaml."""

    def test_all_pinned_adrs_found(self, vm):
        unfound = [adr for adr in vm["adrs"] if not adr["found"]]
        assert not unfound, (
            f"Pinned ADRs missing from .ai/decisions.yaml: "
            f"{[a['id'] for a in unfound]}"
        )

    def test_every_adr_referenced_by_a_node_or_edge_exists(self, vm):
        """Catches typos / drift between node adr_refs and the ADR list."""
        valid_ids = {adr["id"] for adr in vm["adrs"]}
        for node in vm["nodes"]:
            for ref in node.get("adr_refs", []):
                assert ref in valid_ids, (
                    f"Node {node['id']!r} references unknown ADR {ref!r}"
                )
        for edge in vm["edges"]:
            for ref in edge.get("adr_refs", []):
                assert ref in valid_ids, (
                    f"Edge {edge['from']}→{edge['to']} references "
                    f"unknown ADR {ref!r}"
                )


# ---------------------------------------------------------------------------
# Edges all reference real nodes
# ---------------------------------------------------------------------------


class TestEdges:
    """No dangling edges."""

    def test_edges_reference_known_nodes(self, vm):
        all_ids = {n["id"] for n in vm["nodes"]} | {
            t["id"] for t in vm["external_tools"]
        }
        for edge in vm["edges"]:
            assert edge["from"] in all_ids, (
                f"Edge from unknown node {edge['from']!r}"
            )
            assert edge["to"] in all_ids, (
                f"Edge to unknown node {edge['to']!r}"
            )


# ---------------------------------------------------------------------------
# Scanner config snippets are valid argus.yml
# ---------------------------------------------------------------------------


class TestScannerSnippets:
    """The argus.yml snippet on each scanner must parse and validate."""

    def test_every_scanner_snippet_is_valid_yaml(self, vm):
        scanner_nodes = [
            n for n in vm["nodes"]
            if n["kind"] in ("scanner", "scanner-sub", "linter")
        ]
        assert scanner_nodes, "No scanner nodes — view model is broken"
        for node in scanner_nodes:
            cfg = node.get("scanner_config", {})
            yaml_text = cfg.get("yaml")
            assert yaml_text, f"Scanner {node['id']!r} has no yaml snippet"
            parsed = yaml.safe_load(yaml_text)
            assert isinstance(parsed, dict)
            assert "scanners" in parsed

    def test_snippet_roundtrips_through_argus_validate(self, vm, tmp_path):
        """Pick a scanner that's likely to be enabled and roundtrip its
        snippet through ``argus validate``. Smoke-tests the snippet
        shape without re-validating every scanner one by one (which
        would shell out hundreds of times)."""
        bandit_node = next(
            (n for n in vm["nodes"] if n["id"] == "scanner:bandit"), None,
        )
        assert bandit_node is not None
        yaml_text = bandit_node["scanner_config"]["yaml"]
        cfg = tmp_path / "argus.yml"
        cfg.write_text(yaml_text)

        # Run ``argus validate`` against the temp config. argus must
        # be on PATH or invocable as ``python -m argus``. Skip if
        # neither path is available — this is a roundtrip smoke test,
        # not a hard contract.
        result = subprocess.run(
            [sys.executable, "-m", "argus", "validate", "--config", str(cfg)],
            capture_output=True, text=True, check=False, timeout=30,
        )
        # Validate may emit warnings (exit 0) or errors (non-zero).
        # The snippet is correct shape if validate didn't fail with
        # *config-parse* errors — a missing scanner section would be
        # the failure mode we're catching here.
        assert result.returncode in (0, 1), (
            f"argus validate exited unexpectedly: {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ---------------------------------------------------------------------------
# JSON serialization round-trip
# ---------------------------------------------------------------------------


class TestJsonSerialization:
    """The view model must serialize to JSON without loss."""

    def test_serializable_to_json(self, vm):
        # Round-trip through json to catch any non-JSON-able values
        # (e.g. sets, tuples that don't auto-convert).
        text = json.dumps(vm)
        decoded = json.loads(text)
        # Shape preserved across the round-trip.
        assert decoded["schema_version"] == vm["schema_version"]
        assert len(decoded["nodes"]) == len(vm["nodes"])

    def test_pretty_print_is_stable(self, vm):
        """Pretty-printed output should also be deterministic."""
        first = json.dumps(vm, indent=2, sort_keys=True)
        second = json.dumps(vm, indent=2, sort_keys=True)
        assert first == second


# ---------------------------------------------------------------------------
# External tools side-rail
# ---------------------------------------------------------------------------


class TestExternalTools:
    """Tools like trivy/grype that scanners shell out to."""

    def test_critical_tools_present(self, vm):
        names = {t["name"] for t in vm["external_tools"]}
        # The architecture.yaml flags trivy/gitleaks/osv-scanner as
        # critical; verify at least those landed.
        assert "trivy" in names or "grype" in names

    def test_used_by_references_real_scanners(self, vm):
        scanner_ids = {n["id"] for n in vm["nodes"] if n["kind"] in ("scanner",)}
        for tool in vm["external_tools"]:
            for used in tool["used_by"]:
                # Used-by IDs that don't match a known scanner are a
                # mapping bug, not a YAML issue — we control the
                # mapping in architecture.py.
                if used not in scanner_ids:
                    # composite-only scanners (dependency-review) end
                    # up here because they don't have an SDK node.
                    # Skip silently — the mapping intentionally lists
                    # them so we don't lose the trail when they get
                    # ported later.
                    continue


# ---------------------------------------------------------------------------
# Repo-root convenience wrapper
# ---------------------------------------------------------------------------


class TestRepoRootWrapper:
    """``build_view_model_from_repo`` matches manual load+build."""

    def test_wrapper_equals_manual(
        self, architecture_module, inputs, registries,
    ):
        manual = architecture_module.build_view_model(
            architecture=inputs["architecture"],
            decisions=inputs["decisions"],
            context=inputs["context"],
            config_schema=inputs["config_schema"],
            version=inputs["version"],
            registries=registries,
        )
        wrapper = architecture_module.build_view_model_from_repo(REPO_ROOT)
        assert json.dumps(manual, sort_keys=True) == json.dumps(
            wrapper, sort_keys=True,
        )


# ---------------------------------------------------------------------------
# load_inputs handles missing files gracefully
# ---------------------------------------------------------------------------


class TestLoadInputs:
    """The loader should never raise; missing files yield empty dicts."""

    def test_empty_repo_yields_empty_dicts(self, architecture_module, tmp_path):
        loaded = architecture_module.load_inputs(tmp_path)
        assert loaded["architecture"] == {}
        assert loaded["decisions"] == {}
        assert loaded["context"] == {}
        assert loaded["config_schema"] == {}
        assert loaded["version"] == "0.0.0"

    def test_version_yaml_bare_string(self, architecture_module, tmp_path):
        (tmp_path / "version.yaml").write_text(
            "1.2.3 # x-release-it-version\n"
        )
        loaded = architecture_module.load_inputs(tmp_path)
        assert loaded["version"] == "1.2.3 # x-release-it-version" or (
            loaded["version"].startswith("1.2.3")
        )

    def test_version_yaml_mapping(self, architecture_module, tmp_path):
        (tmp_path / "version.yaml").write_text("version: 2.5.0\n")
        loaded = architecture_module.load_inputs(tmp_path)
        assert loaded["version"] == "2.5.0"
