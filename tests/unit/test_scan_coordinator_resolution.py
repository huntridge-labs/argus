"""The scan-coordinator's scanner resolution, executed rather than read.

``reusable-security-hardening.yml``'s ``resolve`` step turns the
``scanners`` and legacy ``scan_type`` inputs into the ``run_*`` outputs
every downstream job is gated on. Two properties matter and pull in
opposite directions:

* it must **fail closed** — an unrecognised name exits 1 rather than
  falling back to the default set, because substituting a full run for
  a request nobody made produces a green tick attesting to the wrong
  thing;
* it must **accept everything it documents** — a hard refusal of a
  valid value is an outage for that caller.

A second hardcoded list of valid ``scan_type`` values broke the second
property while defending the first: ``scan_type: secrets-only`` is
documented on the ``scanners`` input and handled by ``apply_token``'s
``secrets|secrets-only`` branch, yet the ``scan_type`` case rejected it
outright. Nothing caught it, because nothing in this repo executed this
script — the coverage was structural.

These tests run the real ``run:`` body in bash and read the outputs it
writes, so both properties are pinned by behaviour.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest
import yaml

WORKFLOW = (
    pathlib.Path(__file__).resolve().parents[2]
    / ".github" / "workflows" / "reusable-security-hardening.yml"
)


def _bash4() -> str | None:
    """Return a bash >= 4, or None.

    The script uses ``declare -A``, so bash 3.2 — still the system bash
    on macOS — cannot run it at all. GitHub runners are bash 5, so this
    skips locally and executes in CI rather than forcing the workflow
    to avoid associative arrays for a shell it never runs on.
    """
    for candidate in ("bash", "/opt/homebrew/bin/bash", "/usr/local/bin/bash"):
        path = shutil.which(candidate) if "/" not in candidate else candidate
        if not path or not os.path.exists(path):
            continue
        proc = subprocess.run(
            [path, "-c", 'echo "${BASH_VERSINFO[0]}"'],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip().isdigit():
            if int(proc.stdout.strip()) >= 4:
                return path
    return None


BASH4 = _bash4()

bash_required = pytest.mark.skipif(
    BASH4 is None,
    reason="resolution script uses `declare -A`, which needs bash >= 4",
)


def _resolve_script() -> str:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    steps = workflow["jobs"]["scan-coordinator"]["steps"]
    return next(s for s in steps if s.get("id") == "resolve")["run"]


def _resolve(tmp_path, scanners: str = "", scan_type: str = ""):
    """Run the step and return ``(returncode, outputs, combined log)``."""
    github_output = tmp_path / "github_output"
    github_output.touch()
    proc = subprocess.run(
        [BASH4, "-c", _resolve_script()],
        cwd=tmp_path,
        env={
            **os.environ,
            "GITHUB_OUTPUT": str(github_output),
            "SCANNERS_INPUT": scanners,
            "SCAN_TYPE_INPUT": scan_type,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    outputs = dict(
        line.split("=", 1)
        for line in github_output.read_text().splitlines()
        if "=" in line
    )
    return proc.returncode, outputs, proc.stdout + proc.stderr


def _selected(outputs) -> set[str]:
    return {
        key[len("run_"):]
        for key, value in outputs.items()
        if key.startswith("run_") and key != "run_any" and value == "true"
    }


# ── accepts what it documents ───────────────────────────────────────

@bash_required
def test_legacy_scan_type_secrets_only_runs_gitleaks(tmp_path):
    """The regression: documented, handled by apply_token, yet refused.

    ``secrets-only`` is listed on the ``scanners`` input description and
    has an ``apply_token`` branch. A second list of valid ``scan_type``
    values omitted it, so the caller got "Unknown scan type. Nothing was
    run." for a value the same step understands.
    """
    rc, outputs, log = _resolve(tmp_path, scan_type="secrets-only")
    assert rc == 0, log
    assert _selected(outputs) == {"gitleaks"}


@bash_required
@pytest.mark.parametrize(
    ("scan_type", "expected"),
    [
        ("codeql-only", {"codeql"}),
        ("container-only", {"container"}),
        ("CONTAINER_ONLY", {"container"}),  # normalize() folds case + underscore
    ],
)
def test_legacy_scan_types_still_resolve(tmp_path, scan_type, expected):
    rc, outputs, log = _resolve(tmp_path, scan_type=scan_type)
    assert rc == 0, log
    assert _selected(outputs) == expected


@bash_required
def test_full_and_empty_mean_the_default_set(tmp_path):
    rc_full, out_full, _ = _resolve(tmp_path, scan_type="full")
    rc_empty, out_empty, _ = _resolve(tmp_path, scan_type="")
    assert (rc_full, rc_empty) == (0, 0)
    assert _selected(out_full) == _selected(out_empty)
    assert "codeql" in _selected(out_full)


# ── and still fails closed ──────────────────────────────────────────

@bash_required
def test_unknown_scan_type_refuses_rather_than_running_everything(tmp_path):
    """Falling back to the default set is the failure mode, not exiting 1.

    Routing an unrecognised scan_type through the token loop must not
    soften this: the caller asked for something specific, and a full run
    reported green would attest to a request nobody made.
    """
    rc, outputs, log = _resolve(tmp_path, scan_type="bogus-only")
    assert rc != 0, "an unrecognised scan_type must not run anything"
    assert _selected(outputs) == set()
    assert "bogus-only" in log


@bash_required
def test_unknown_scanner_name_refuses(tmp_path):
    rc, outputs, log = _resolve(tmp_path, scanners="tryvi")
    assert rc != 0
    assert _selected(outputs) == set()
    assert "tryvi" in log


@bash_required
def test_every_unknown_name_is_named_in_one_run(tmp_path):
    """A caller with two typos should not have to iterate twice."""
    rc, _outputs, log = _resolve(tmp_path, scanners="tryvi,bandet")
    assert rc != 0
    assert "tryvi" in log and "bandet" in log


@bash_required
def test_scanners_input_wins_over_scan_type(tmp_path):
    """scan_type is only consulted when scanners is unset or 'default'."""
    rc, outputs, log = _resolve(
        tmp_path, scanners="bandit", scan_type="container-only",
    )
    assert rc == 0, log
    assert _selected(outputs) == {"bandit"}
