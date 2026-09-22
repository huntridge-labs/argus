"""Contract test: container-scan.yml's count outputs have one source.

``container-scan.yml`` scans from two jobs — ``build-and-scan`` (matrix,
one leg per discovered Dockerfile) and ``scan-remote-image`` (single, a
pre-existing image ref) — and both feed the workflow's ``critical_count``
/ ``images_scanned`` / ``overall_status`` outputs, which are a public
contract for callers.

Those two jobs each used to map ``argus-results.json``'s field names onto
the counts artifact. The copies were identical, so a one-sided edit —
renaming a key, or changing the images-counted-on-failure fallback —
would silently skew every count for one scan mode while the other stayed
correct, and nothing in CI would notice.

The mapping now lives once, in the summary job. The scan jobs forward
every top-level number without naming a field, so there is nothing left
for them to disagree about. These tests pin that arrangement:

* the two scan steps stay character-identical (they are still duplicated
  in the parts that carry no drift risk, e.g. the PLATFORM_ARGS builder);
* each count field name appears exactly once in the whole workflow;
* the scan's exit code still survives the counts bookkeeping.
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


# The jq reads that pull argus-results.json's fields into the count
# outputs. Matched as the full jq expression, not the bare field name —
# `critical_count` also appears as a workflow output name several times
# over, which a substring check would wrongly count as duplication.
COUNT_READS = [
    "jq -r '.critical_count // 0'",
    "jq -r '.high_count // 0'",
    "jq -r '.medium_count // 0'",
    "jq -r '.low_count // 0'",
    "jq -r '.total_count // 0'",
]


@pytest.mark.parametrize("read", COUNT_READS)
def test_each_count_field_is_mapped_exactly_once(read):
    """One source of truth, enforced by count.

    Two occurrences means the mapping has been duplicated back into the
    scan jobs and can drift again; zero means an output silently lost its
    source and will report 0 forever.
    """
    text = WORKFLOW.read_text()
    assert text.count(read) == 1, (
        f"{read} appears {text.count(read)}x in container-scan.yml; "
        "the mapping onto the workflow_call count outputs must exist in "
        "exactly one place (the summary job)"
    )


def test_scan_jobs_do_not_name_count_fields():
    """The scan jobs forward numbers generically; only the summary maps."""
    for job in SCAN_JOBS:
        script = _scan_script(job)
        for read in COUNT_READS:
            assert read not in script, (
                f"{job} performs {read} again — that is the duplication "
                "this arrangement removed"
            )


def test_incomplete_scans_are_excluded_from_images_scanned():
    """`images_scanned` is how a caller tells clean from never-ran."""
    text = WORKFLOW.read_text()
    assert text.count("argus_scan_incomplete") >= 3, (
        "both scan jobs must emit the sentinel and the summary must honour it"
    )
    summary = _workflow()["jobs"]["container-scan-summary"]
    agg = next(s for s in summary["steps"] if s.get("id") == "counts")["run"]
    assert "argus_scan_incomplete" in agg
    assert "IMAGES=$((IMAGES + 1))" in agg


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


# ── The aggregation script, executed ────────────────────────────────
#
# The tests above pin the shape of container-scan.yml. These run the
# summary job's `counts` script for real, because the bug they guard
# against was invisible to a structural check: the incomplete sentinel
# was parsed, warned about, and then had no effect on `overall_status`.
# A run with one clean image and one that never scanned reported
# `success`.

import json
import os
import shutil
import subprocess


def _aggregation_script() -> str:
    summary = _workflow()["jobs"]["container-scan-summary"]
    return next(
        s for s in summary["steps"] if s.get("id") == "counts"
    )["run"]


def _run_aggregation(tmp_path, counts: list[dict], **job_results) -> dict:
    """Execute the counts script over ``counts`` and return its outputs.

    ``counts`` is one dict per published artifact — real count payloads
    or the ``{"argus_scan_incomplete": true}`` sentinel. ``job_results``
    override the four job-result env vars, which default to success.
    """
    counts_dir = tmp_path / "scanner-counts"
    counts_dir.mkdir()
    for i, payload in enumerate(counts):
        (counts_dir / f"leg-{i}.json").write_text(json.dumps(payload))

    github_output = tmp_path / "github_output"
    github_output.touch()
    env = {
        **os.environ,
        "GITHUB_OUTPUT": str(github_output),
        "BUILD_SCAN_RESULT": job_results.get("build", "success"),
        "REMOTE_SCAN_RESULT": job_results.get("remote", "skipped"),
        "VALIDATE_RESULT": job_results.get("validate", "success"),
        "DISCOVER_RESULT": job_results.get("discover", "success"),
    }
    proc = subprocess.run(
        ["bash", "-c", _aggregation_script()],
        cwd=tmp_path, env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return dict(
        line.split("=", 1)
        for line in github_output.read_text().splitlines()
        if "=" in line
    )


jq_required = pytest.mark.skipif(
    shutil.which("jq") is None, reason="aggregation script needs jq",
)


@jq_required
def test_clean_run_reports_success(tmp_path):
    out = _run_aggregation(
        tmp_path, [{"critical_count": 0, "total_count": 0}],
    )
    assert out["overall_status"] == "success"
    assert out["images_scanned"] == "1"


@jq_required
def test_one_incomplete_leg_among_clean_ones_is_not_success(tmp_path):
    """The mixed case — the common one, and the one that was silent.

    `IMAGES -eq 0` only catches a run where *every* leg failed. With one
    image scanning cleanly, IMAGES is 1, that guard never fires, and a
    caller gating on `overall_status` was told a run containing a
    completely unscanned image was clean.
    """
    out = _run_aggregation(
        tmp_path,
        [
            {"critical_count": 0, "total_count": 0},
            {"argus_scan_incomplete": True},
        ],
    )
    assert out["overall_status"] == "failure"
    assert out["images_scanned"] == "1", (
        "the incomplete leg must still be excluded from images_scanned"
    )


@jq_required
def test_every_leg_incomplete_is_not_success(tmp_path):
    out = _run_aggregation(tmp_path, [{"argus_scan_incomplete": True}])
    assert out["overall_status"] == "failure"
    assert out["images_scanned"] == "0"


@jq_required
def test_no_counts_at_all_reports_skipped(tmp_path):
    """Nothing failed, nothing ran — still never `success`."""
    out = _run_aggregation(tmp_path, [])
    assert out["overall_status"] == "skipped"


@jq_required
def test_counts_are_summed_across_legs(tmp_path):
    out = _run_aggregation(
        tmp_path,
        [
            {"critical_count": 1, "high_count": 2, "total_count": 3},
            {"critical_count": 4, "high_count": 0, "total_count": 4},
        ],
    )
    assert out["critical_count"] == "5"
    assert out["high_count"] == "2"
    assert out["total_count"] == "7"
    assert out["images_scanned"] == "2"
    assert out["vulnerabilities_found"] == "true"
