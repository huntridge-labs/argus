"""Contract test for reusable scanner workflows (issue #322).

The `security-summary` aggregator stitches the consolidated PR comment's
findings detail from artifacts matching ``scanner-summary-*``. Leaf scanner
reusable workflows that run the CLI inline must therefore each upload a
``scanner-summary-<name>`` artifact — otherwise their findings silently vanish
from the aggregated comment (the #322 regression).

This test locks that contract in so a new or edited scanner workflow can't
quietly drop the summary upload again.
"""

from __future__ import annotations

import pathlib

import yaml

WORKFLOWS = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows"

# CLI-inline leaf scanners that feed the consolidated comment. codeql / syft /
# dependency-review delegate to composite actions that emit their own
# scanner-summary-* artifact. The direct scanner-zap.yml workflow runs the CLI
# inline and posts its own PR comment, so it must emit scanner-summary-zap too
# (scanner-zap-from-config.yml is the separate matrix path that aggregates via
# the scanner-zap-summary composite action). New inline scanners should be
# added here (and emit a scanner-summary-* artifact).
CLI_SCANNERS = [
    "bandit",
    "checkov",
    "clamav",
    "gitleaks",
    "opengrep",
    "osv",
    "supply-chain",
    "trivy-iac",
    "grype",
    "trivy-container",
    "zap",
]


def _uploaded_artifact_names(workflow: pathlib.Path) -> list[str]:
    data = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    names: list[str] = []
    for job in (data.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            uses = step.get("uses", "") if isinstance(step, dict) else ""
            if isinstance(uses, str) and "upload-artifact" in uses:
                names.append(str((step.get("with") or {}).get("name", "")))
    return names


def test_cli_scanner_workflows_emit_scanner_summary_artifact():
    missing = []
    for scanner in CLI_SCANNERS:
        wf = WORKFLOWS / f"scanner-{scanner}.yml"
        assert wf.is_file(), f"missing reusable workflow: {wf.name}"
        names = _uploaded_artifact_names(wf)
        if not any(n.startswith(f"scanner-summary-{scanner}") for n in names):
            missing.append(scanner)
    assert not missing, (
        "reusable scanner workflows missing a scanner-summary-<name> artifact "
        f"(findings would be dropped from the consolidated comment, #322): {missing}"
    )
