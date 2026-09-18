"""Contract test: container-scan.yml's two scan jobs must not drift apart.

``container-scan.yml`` runs the scan from two jobs — ``build-and-scan``
(matrix, one entry per discovered Dockerfile) and ``scan-remote-image``
(single, a pre-existing image ref). Their scan steps are character-for-
character identical: the same ``PLATFORM_ARGS`` builder, the same argus
invocation, and the same jq mapping from ``argus-results.json`` onto the
per-image counts artifact that the summary job aggregates into the
workflow's ``critical_count`` / ``images_scanned`` / ``overall_status``
outputs.

Those outputs are a public contract for callers, and the duplication is
load-bearing: a one-sided edit — renaming an ``argus-results.json`` key,
or changing the images-counted-on-failure fallback — would silently skew
every count for one scan mode while the other stayed correct. Nothing in
CI would notice, because each mode's own run would still be internally
consistent.

Carrying the block once, as a composite action under ``.github/actions/``,
is the real fix. It is deferred rather than dismissed: a reusable workflow's
``run:`` steps execute against the *caller's* checkout, so a shared script
in this repo would simply not exist for consumers, and a new composite
action has to be referenced as ``huntridge-labs/argus/.github/actions/
<name>@<tag>`` — a tag that will not contain it until release-it cuts the
next release. It therefore has to land in the same release as its first
use. Until then this test is the guard: it fails the moment the two copies
stop matching.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

WORKFLOW = (
    pathlib.Path(__file__).resolve().parents[2]
    / ".github" / "workflows" / "container-scan.yml"
)

# The two jobs whose scan steps must stay identical.
SCAN_JOBS = ("build-and-scan", "scan-remote-image")


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _scan_script(job: str) -> str:
    """Return the `run:` body of the job's `id: scan` step."""
    steps = _workflow()["jobs"][job]["steps"]
    for step in steps:
        if step.get("id") == "scan":
            return step["run"]
    raise AssertionError(f"{job} has no step with `id: scan`")


def _significant_lines(script: str) -> list[str]:
    """Drop comments and blank lines — the copies may be commented differently."""
    return [
        line.rstrip()
        for line in script.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def test_both_scan_jobs_exist():
    jobs = _workflow()["jobs"]
    for job in SCAN_JOBS:
        assert job in jobs, f"{job} disappeared from container-scan.yml"


def test_scan_steps_are_identical():
    """The whole block, not just the counts — argus flags must match too."""
    build, remote = (_significant_lines(_scan_script(j)) for j in SCAN_JOBS)
    assert build == remote, (
        "container-scan.yml's two scan steps have drifted.\n"
        "They feed the same workflow_call count outputs, so a one-sided edit "
        "skews those outputs for one scan mode only, silently.\n"
        "Re-sync them, or extract the block into a composite action and update "
        "this test."
    )


@pytest.mark.parametrize(
    "fragment",
    [
        'PLATFORM_ARGS=()',
        'critical: (.critical_count // 0)',
        'high: (.high_count // 0)',
        'medium: (.medium_count // 0)',
        'low: (.low_count // 0)',
        'total: (.total_count // 0)',
        'images: 1',
        '"images":0',
        'exit $SCAN_EXIT',
    ],
)
def test_counts_contract_present_in_both_jobs(fragment):
    """Pin the specific pieces the workflow outputs are computed from.

    `images: 1` on success and `"images":0` on a missing results file are
    how a caller tells "clean" from "never ran" via `images_scanned`.
    """
    for job in SCAN_JOBS:
        assert fragment in _scan_script(job), (
            f"{job}'s scan step no longer contains {fragment!r} — the "
            "workflow_call count outputs depend on it"
        )


def test_scan_exit_code_is_preserved():
    """The severity-threshold verdict must survive the counts bookkeeping.

    The step captures the CLI's exit code, copies artifacts, then re-exits
    with it. Dropping the re-exit would turn a findings-over-threshold run
    green — a silent pass of exactly the kind this workflow's own
    validate-inputs job exists to prevent.
    """
    for job in SCAN_JOBS:
        script = _scan_script(job)
        assert "|| SCAN_EXIT=$?" in script
        assert script.rstrip().endswith("exit $SCAN_EXIT")
