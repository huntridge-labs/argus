"""Lint for the CLI image's path-scoped trivy / grype ignore files.

``.vex/argus-cli.trivyignore.yaml`` and ``.vex/argus-cli.grype.yaml`` replace
the OpenVEX statements the CLI image used to carry for the gitleaks binary.
OpenVEX names only a component PURL, so those statements hid the same CVEs in
any Go binary built with the same toolchain; these rules are scoped to
``usr/local/bin/gitleaks``. The checks below keep them scoped, justified, and
spelled the way each tool expects. The post-scan guard in
``scripts/ci/render_container_summary.py`` catches a rule that matched nothing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
VEX_DIR = REPO_ROOT / ".vex"
TRIVY_PATH = VEX_DIR / "argus-cli.trivyignore.yaml"
GRYPE_PATH = VEX_DIR / "argus-cli.grype.yaml"
GITLEAKS = "usr/local/bin/gitleaks"


def _trivy_rules() -> list[dict]:
    return yaml.safe_load(TRIVY_PATH.read_text(encoding="utf-8"))["vulnerabilities"]


def _grype_rules() -> list[dict]:
    return yaml.safe_load(GRYPE_PATH.read_text(encoding="utf-8"))["ignore"]


@pytest.mark.parametrize("rule", _trivy_rules(), ids=lambda r: r["id"])
def test_trivy_rule_is_scoped_to_gitleaks_and_justified(rule):
    # trivy matches paths with no leading slash; "/usr/..." matches nothing.
    assert rule["paths"] == [GITLEAKS]
    assert rule["id"].startswith("CVE-"), "trivy reports Go findings by CVE ID"
    assert rule.get("statement", "").strip()


@pytest.mark.parametrize("rule", _grype_rules(), ids=lambda r: r["vulnerability"])
def test_grype_rule_is_scoped_to_gitleaks_and_justified(rule):
    # grype locations carry a leading slash, unlike trivy paths.
    assert rule["package"]["location"] == f"/{GITLEAKS}"
    assert rule["package"].get("name")
    # A grype rule on the CVE ID does not match: grype keys Go findings on
    # GO- IDs and lists the CVE only as a related vulnerability.
    assert rule["vulnerability"].startswith(("GO-", "GHSA-"))
    assert rule.get("reason", "").strip()


def test_grype_config_holds_only_ignore_rules():
    # The file is passed as grype's whole config (-c); anything else in it
    # would change how the CLI image is scanned, not just what is ignored.
    assert set(yaml.safe_load(GRYPE_PATH.read_text(encoding="utf-8"))) == {"ignore"}


def test_cli_openvex_document_is_gone():
    # Its statements were unscoped. Reintroducing it for gitleaks would hide
    # these CVEs in every Go binary again.
    assert not (VEX_DIR / "argus-cli.openvex.json").exists()


def test_build_containers_passes_both_files():
    workflow = (REPO_ROOT / ".github" / "workflows" / "build-containers.yml").read_text()
    assert "--trivy-ignore-file .vex/argus-cli.trivyignore.yaml" in workflow
    assert "--grype-config-file .vex/argus-cli.grype.yaml" in workflow
    assert "--vex .vex/argus-cli.openvex.json" not in workflow


def test_argus_yml_passes_both_files():
    containers = yaml.safe_load((REPO_ROOT / "argus.yml").read_text())["containers"]
    assert containers["trivy_ignore_file"] == ".vex/argus-cli.trivyignore.yaml"
    assert containers["grype_config_file"] == ".vex/argus-cli.grype.yaml"
    assert "vex" not in containers
