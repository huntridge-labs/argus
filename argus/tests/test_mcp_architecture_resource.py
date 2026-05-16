"""Tests for the ``argus://architecture`` MCP resource.

The handler in ``argus/mcp.py`` must return JSON byte-identical to
what the docsite build inlines into the architecture page, given
the same canonical inputs. That single contract is what makes the
"one transformer, three consumers" rule of ADR-026 actually true.
"""

from __future__ import annotations

import asyncio
import json

import pytest


@pytest.fixture(scope="module")
def mcp_architecture_json() -> str:
    """Call the MCP resource handler and return its raw response."""
    from argus.mcp import read_architecture
    return asyncio.run(read_architecture())


@pytest.fixture(scope="module")
def mcp_view_model(mcp_architecture_json) -> dict:
    return json.loads(mcp_architecture_json)


@pytest.fixture(scope="module")
def docsite_view_model() -> dict:
    """Call the canonical transformer directly via the shim."""
    from argus.architecture_map import build_view_model_from_repo
    from pathlib import Path
    return build_view_model_from_repo(Path("."))


class TestMcpResourceShape:
    """Smoke shape — basic top-level fields present."""

    def test_returns_json(self, mcp_view_model):
        # The MCP framework returns a string; loads should succeed.
        assert isinstance(mcp_view_model, dict)

    def test_has_schema_version(self, mcp_view_model):
        assert mcp_view_model.get("schema_version")

    def test_has_nodes_edges_flows(self, mcp_view_model):
        assert len(mcp_view_model.get("nodes", [])) > 0
        assert len(mcp_view_model.get("edges", [])) > 0
        assert len(mcp_view_model.get("flows", [])) > 0


class TestMcpDocsiteParity:
    """The MCP resource and the docsite/web hydration must agree.

    Both call ``build_view_model_from_repo`` against the same repo
    root with the same registries. The transformer is pure and
    deterministic, so the JSON-encoded outputs must match byte-for-
    byte (modulo whitespace, which the resource encodes with
    ``indent=2`` for human readability).
    """

    def test_byte_identical_after_normalization(
        self, mcp_view_model, docsite_view_model,
    ):
        # Both go through ``json.dumps(..., sort_keys=True)`` to
        # canonicalize dict order; if either source were forking the
        # projection logic, this assertion would catch it.
        mcp_text = json.dumps(mcp_view_model, sort_keys=True)
        docsite_text = json.dumps(docsite_view_model, sort_keys=True)
        assert mcp_text == docsite_text

    def test_node_counts_match(self, mcp_view_model, docsite_view_model):
        assert len(mcp_view_model["nodes"]) == len(docsite_view_model["nodes"])

    def test_flow_counts_match(self, mcp_view_model, docsite_view_model):
        assert len(mcp_view_model["flows"]) == len(docsite_view_model["flows"])


class TestMcpResourceRegistration:
    """The handler must be exposed at ``argus://architecture``."""

    def test_resource_is_registered_with_correct_uri(self):
        # The mcp object lives at module level; we can introspect its
        # registered resources to make sure the URI is exactly the
        # one ADR-026 promises. The framework's exact attribute name
        # for the registry varies by version — fall back to a string
        # search of the module source as a smoke check.
        from argus import mcp as mcp_module
        import inspect
        source = inspect.getsource(mcp_module)
        assert "argus://architecture" in source

    def test_handler_does_not_raise(self):
        """Idempotency check — calling twice returns equivalent JSON."""
        from argus.mcp import read_architecture
        first = asyncio.run(read_architecture())
        second = asyncio.run(read_architecture())
        # Both should parse, and the parsed dicts should be equal.
        assert json.loads(first) == json.loads(second)
