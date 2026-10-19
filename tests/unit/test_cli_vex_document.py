"""Lint for ``.vex/argus-cli.openvex.json``, the CLI container's VEX.

trivy and grype drop a finding only when a statement's product PURL matches
theirs exactly, and say nothing when it does not. The document spelled Go's
version ``go1.24.11`` (govulncheck's spelling) while trivy reports
``v1.24.11`` and grype ``1.24.11``, so the two criticals it covers stayed in
every PR comment. These checks keep that class of miss out of the file; the
post-scan guard in ``render_container_summary`` catches anything else.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
VEX_PATH = REPO_ROOT / ".vex" / "argus-cli.openvex.json"
STDLIB_PREFIX = "pkg:golang/stdlib@"


def _statements() -> list[dict]:
    return json.loads(VEX_PATH.read_text(encoding="utf-8"))["statements"]


def _product_ids(statement: dict) -> list[str]:
    return [product["@id"] for product in statement["products"]]


@pytest.mark.parametrize("statement", _statements(), ids=lambda s: s["vulnerability"]["name"])
def test_statement_is_justified(statement):
    assert statement["status"] == "not_affected"
    assert statement.get("justification")
    assert statement.get("impact_statement")


@pytest.mark.parametrize("statement", _statements(), ids=lambda s: s["vulnerability"]["name"])
def test_stdlib_products_use_both_scanner_spellings(statement):
    versions = [pid[len(STDLIB_PREFIX):] for pid in _product_ids(statement)
                if pid.startswith(STDLIB_PREFIX)]
    if not versions:
        pytest.skip("not a Go stdlib statement")

    assert not [v for v in versions if v.startswith("go")], (
        "trivy and grype never emit go-prefixed stdlib versions"
    )
    bare = {v.removeprefix("v") for v in versions}
    for version in bare:
        assert f"v{version}" in versions, f"trivy spelling v{version} missing"
        assert version in versions, f"grype spelling {version} missing"


def test_build_containers_applies_this_document():
    workflow = (REPO_ROOT / ".github" / "workflows" / "build-containers.yml").read_text()
    assert "--vex .vex/argus-cli.openvex.json" in workflow
