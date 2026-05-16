#!/usr/bin/env python3
"""Audit example workflows against current action.yml input contracts.

Why this exists
===============

Composite-action consumers passing inputs that aren't declared in
``action.yml::inputs`` see a runtime warning, not a failure. CI never
*runs* the example workflows — it only validates their YAML syntax.
That gap let a pre-1.0.0 contract trim drift through unnoticed: every
``examples/workflows/actions-scanner-zap-*.yml`` and several
``examples/github-enterprise/*.yml`` kept passing inputs that
``scanner-zap`` / ``scanner-container`` / ``scanner-gitleaks`` had
already removed. Surfaced during an external GHES consumer migration
audit and fixed in PR #134.

This script closes the gap: it parses every action's ``action.yml``
to build the source-of-truth input list, walks every example
workflow's ``with:`` blocks for ``uses: huntridge-labs/argus/.github/
actions/<name>@<ref>`` steps, and reports any ``with:`` key that
isn't in the action's current contract. Run from CI, this prevents
the next contract trim from silently breaking the docs.

Usage
=====

    python -m scripts.ci.check_example_inputs              # all examples
    python -m scripts.ci.check_example_inputs --paths examples/workflows
    python -m scripts.ci.check_example_inputs --json       # machine-readable

Exit codes
==========

* 0 — every ``with:`` key is declared in the matching action.yml
* 1 — at least one unknown key found (failure list printed)
* 2 — internal error (couldn't parse an action.yml, etc.)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterator

import yaml


# Composite actions live here. Source of truth for input names.
ARGUS_ACTIONS_DIR = Path(".github/actions")

# Examples whose with: blocks we audit. Two roots cover all canonical
# consumer-facing patterns:
#   examples/workflows/         — composite-action-based examples
#   examples/github-enterprise/ — GHES-targeted examples
DEFAULT_EXAMPLE_ROOTS = ("examples/workflows", "examples/github-enterprise")

# Action references look like
#   uses: huntridge-labs/argus/.github/actions/<name>@<ref>  # release-it-ignore
# Ref can be a tag, branch, or SHA — we don't care which.
_ACTION_USES_RE = re.compile(
    r"^huntridge-labs/argus/\.github/actions/([^@]+)@"
)


def collect_action_inputs(actions_dir: Path) -> dict[str, set[str]]:
    """Return ``{action_name: {input_name, ...}}`` for every action.yml.

    Missing or unparsable ``action.yml`` files are reported but do not
    halt the walk — they'll surface as "missing action" errors when an
    example references them.
    """
    out: dict[str, set[str]] = {}
    for action_dir in sorted(actions_dir.iterdir()):
        yml = action_dir / "action.yml"
        if not yml.is_file():
            continue
        try:
            data = yaml.safe_load(yml.read_text()) or {}
        except yaml.YAMLError as exc:
            # Surface but don't halt — a broken action.yml is a
            # different bug class.
            print(
                f"::warning file={yml}::failed to parse action.yml: {exc}",
                file=sys.stderr,
            )
            continue
        out[action_dir.name] = set((data.get("inputs") or {}).keys())
    return out


def iter_example_workflows(roots: tuple[str, ...]) -> Iterator[Path]:
    """Yield every ``*.yml`` under the given example roots."""
    for root in roots:
        root_path = Path(root)
        if not root_path.is_dir():
            continue
        yield from sorted(root_path.rglob("*.yml"))


def audit_workflow(
    wf: Path,
    action_inputs: dict[str, set[str]],
) -> list[dict]:
    """Return one issue dict per problem in *wf*.

    Each issue has ``file``, ``job``, ``step``, ``action``, ``kind``,
    and either ``unknown`` (a sorted list of unrecognized keys) or
    ``message`` (free text for missing-action / parse-fail cases).
    """
    issues: list[dict] = []
    try:
        data = yaml.safe_load(wf.read_text())
    except yaml.YAMLError as exc:
        issues.append({
            "file": str(wf),
            "job": None,
            "step": None,
            "action": None,
            "kind": "yaml_parse_error",
            "message": str(exc),
        })
        return issues

    if not isinstance(data, dict):
        return issues
    jobs = data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return issues

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for step in (job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            if not isinstance(uses, str):
                continue
            m = _ACTION_USES_RE.match(uses)
            if not m:
                continue
            action = m.group(1)
            step_name = step.get("name", "?")

            if action not in action_inputs:
                issues.append({
                    "file": str(wf),
                    "job": job_name,
                    "step": step_name,
                    "action": action,
                    "kind": "missing_action",
                    "message": (
                        f"action '{action}' is not present at "
                        f"{ARGUS_ACTIONS_DIR / action}"
                    ),
                })
                continue

            with_keys = set((step.get("with") or {}).keys())
            unknown = with_keys - action_inputs[action]
            if unknown:
                issues.append({
                    "file": str(wf),
                    "job": job_name,
                    "step": step_name,
                    "action": action,
                    "kind": "unknown_input",
                    "unknown": sorted(unknown),
                })

    return issues


def format_human(issues: list[dict]) -> str:
    if not issues:
        return "✓ all example with: keys match current action.yml contracts\n"
    lines = []
    by_file: dict[str, list[dict]] = {}
    for i in issues:
        by_file.setdefault(i["file"], []).append(i)
    for f, group in sorted(by_file.items()):
        lines.append(f"\n{f}:")
        for i in group:
            loc = f"  {i['job'] or '?'}.{i['step'] or '?'}"
            if i["kind"] == "unknown_input":
                lines.append(
                    f"{loc} (action: {i['action']}): unknown with: keys "
                    f"{i['unknown']}"
                )
            elif i["kind"] == "missing_action":
                lines.append(f"{loc}: {i['message']}")
            else:
                lines.append(f"{loc}: {i['kind']} — {i.get('message', '')}")
    lines.append("")
    lines.append(f"{len(issues)} issue(s) found across {len(by_file)} file(s)")
    return "\n".join(lines) + "\n"


def format_actions_annotations(issues: list[dict]) -> str:
    """GitHub Actions ``::error file=...,line=...::message`` annotations."""
    out = []
    for i in issues:
        if i["kind"] == "unknown_input":
            msg = (
                f"action '{i['action']}' does not declare these "
                f"with: keys: {', '.join(i['unknown'])}. "
                f"Compare against {ARGUS_ACTIONS_DIR / i['action']}/action.yml inputs."
            )
        elif i["kind"] == "missing_action":
            msg = i["message"]
        else:
            msg = i.get("message", i["kind"])
        out.append(f"::error file={i['file']}::{msg}")
    return "\n".join(out) + ("\n" if out else "")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n", 1)[0],
    )
    parser.add_argument(
        "--paths", nargs="+", default=list(DEFAULT_EXAMPLE_ROOTS),
        help="Roots to walk for *.yml example files",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit issues as a JSON array on stdout",
    )
    parser.add_argument(
        "--actions-dir", type=Path, default=ARGUS_ACTIONS_DIR,
        help="Directory containing action.yml files",
    )
    parser.add_argument(
        "--gh-annotations", action="store_true",
        help="Also emit ``::error::`` annotations for GitHub Actions UI",
    )
    args = parser.parse_args(argv)

    if not args.actions_dir.is_dir():
        print(
            f"actions directory not found: {args.actions_dir}",
            file=sys.stderr,
        )
        return 2

    action_inputs = collect_action_inputs(args.actions_dir)

    issues: list[dict] = []
    for wf in iter_example_workflows(tuple(args.paths)):
        issues.extend(audit_workflow(wf, action_inputs))

    if args.json:
        json.dump(issues, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(format_human(issues))

    if args.gh_annotations and issues:
        sys.stderr.write(format_actions_annotations(issues))

    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
