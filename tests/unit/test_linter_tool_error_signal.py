"""Contract test for the linter tool-error signal (issue #325).

A linter that *crashes* (the underlying tool errored — argus exit code 2) is a
different signal from a linter that merely *found issues* (exit code 1). Each
linter action must surface a tool error distinctly so it reaches every persona:
the job console (``::error::`` annotation), the check/status summary, and the PR
comment. The mechanism:

* each ``linter-*`` action exposes a ``tool_status`` output ("ok"/"error"),
  derived from the argus exit code, plus an opt-in ``fail_on_tool_error`` input;
* the scan step no longer aborts with ``exit $SCAN_EXIT`` (that would stop the
  composite exporting ``tool_status``); an "Enforce lint failure policy" step
  applies the findings / tool-error gates instead;
* ``linting.yml`` drives the summary status table from each linter's
  ``tool_status`` (reliable) rather than ``needs.*.result`` (masked by
  ``continue-on-error``), and wires the block decision to ``fail_on_tool_error``.

This test locks the contract so a future edit can't silently drop the signal.
"""

from __future__ import annotations

import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
ACTIONS = ROOT / ".github" / "actions"
WORKFLOWS = ROOT / ".github" / "workflows"

LINTERS = ["yaml", "json", "python", "javascript", "dockerfile", "terraform"]


def _action(linter: str) -> pathlib.Path:
    return ACTIONS / f"linter-{linter}" / "action.yml"


def test_linter_actions_expose_tool_status_output_and_gate_input():
    for linter in LINTERS:
        path = _action(linter)
        assert path.is_file(), f"missing linter action: {path}"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        outputs = data.get("outputs") or {}
        inputs = data.get("inputs") or {}
        assert "tool_status" in outputs, f"{linter}: missing tool_status output"
        assert "issues_count" in outputs, f"{linter}: missing issues_count output"
        assert "fail_on_tool_error" in inputs, f"{linter}: missing fail_on_tool_error input"


def test_linter_actions_do_not_abort_before_exporting_outputs():
    # `exit $SCAN_EXIT` in the scan step would stop the composite from exporting
    # tool_status. The failure policy must live in a dedicated enforce step.
    for linter in LINTERS:
        text = _action(linter).read_text(encoding="utf-8")
        assert "exit $SCAN_EXIT" not in text, (
            f"{linter}: scan step still aborts with `exit $SCAN_EXIT`; tool_status "
            "would not propagate to the caller"
        )
        assert "Enforce lint failure policy" in text, (
            f"{linter}: missing the 'Enforce lint failure policy' step"
        )
        assert "tool_status=error" in text and "tool_status=ok" in text, (
            f"{linter}: scan step must emit both tool_status=ok and tool_status=error"
        )
        assert "::error" in text, f"{linter}: missing a ::error:: annotation on tool error"


def test_linting_workflow_drives_table_from_tool_status():
    text = (WORKFLOWS / "linting.yml").read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    inputs = (data.get(True) or data.get("on") or {}).get("workflow_call", {}).get("inputs", {})
    assert "fail_on_tool_error" in inputs, "linting.yml missing fail_on_tool_error input"
    # The status table must key off tool_status, not the maskable needs.*.result.
    assert "_tool_status == 'error'" in text, (
        "linting.yml scan_statuses should derive from each linter's tool_status output"
    )
    assert "fail_on_scanner_failure: ${{ inputs.fail_on_tool_error }}" in text, (
        "linting.yml must gate the summary hard-fail on fail_on_tool_error"
    )
    # Every linter's tool_status must be threaded into scan_statuses.
    for key in ("yaml", "json", "python", "javascript", "dockerfile", "terraform"):
        assert f'"{key}":' in text, f"linting.yml scan_statuses missing linter '{key}'"
