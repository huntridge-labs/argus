"""Issue-keyed ADR records: check, list, and scaffold (ADR-483).

ADRs live in two places:

  - ``.ai/decisions.yaml`` holds the legacy ADR-001 .. ADR-044. Their IDs are
    zero-padded three digits. The file is closed to new entries; existing
    entries can still be edited.
  - ``.ai/decisions/ADR-<issue>.yaml`` holds one ADR per file, keyed to the
    GitHub issue that asked for it. IDs are not padded and are at least
    ``ISSUE_KEYED_FLOOR``, so they can't collide with the legacy range.

Subcommands:

  check  Validate both stores. With ``--branch`` (a PR's head branch) and
         ``--base`` (the commit the PR merges into), also require every ADR
         the PR adds to carry the branch's issue number.
  list   Print every ADR from both stores, sorted by number. This is the
         index; it is built at read time and never committed.
  new    Write a skeleton ``.ai/decisions/ADR-<issue>.yaml`` for the current
         branch's issue.

Run as:
    python -m scripts.ci.adr_records check --branch feat/483-x --base HEAD^1
    python -m scripts.ci.adr_records list
    python -m scripts.ci.adr_records new --title "Short decision title"
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

LEGACY_FILE = Path(".ai/decisions.yaml")
RECORDS_DIR = Path(".ai/decisions")
ARCHITECTURE_FILE = Path(".ai/architecture.yaml")

# Highest ADR number in .ai/decisions.yaml when it was closed to new entries.
LEGACY_LAST = 44
# Lowest issue-keyed ADR number. Comfortably above the legacy range; every
# issue number in this repo is already past it.
ISSUE_KEYED_FLOOR = 100

LEGACY_ID = re.compile(r"^ADR-(\d{3})$")
RECORD_ID = re.compile(r"^ADR-([1-9]\d*)$")
RECORD_FILE = re.compile(r"^ADR-([1-9]\d*)\.yaml$")
# `feat/483-short-description`: the issue number comes right after the prefix.
BRANCH_ISSUE = re.compile(r"^[A-Za-z0-9._-]+/([1-9]\d*)(?:-|$)")
BRANCH_FORMAT = "<prefix>/<issue>-<description>"

REQUIRED_TEXT = {"title": 3, "context": 10, "decision": 5}
STATUSES = ("proposed", "accepted", "rejected", "deprecated", "superseded")
DOCS_POINTER = "see AGENTS.md, 'Issues, branches, and records'"


class DuplicateKeyError(ValueError):
    """Raised when a YAML mapping repeats a key (PyYAML keeps the last one silently)."""


def _check_duplicate_keys(node: yaml.Node) -> None:
    if isinstance(node, yaml.MappingNode):
        seen: set[str] = set()
        for key_node, value_node in node.value:
            key = getattr(key_node, "value", None)
            if isinstance(key, str) and key in seen:
                line = key_node.start_mark.line + 1
                raise DuplicateKeyError(f"duplicate key {key!r} at line {line}")
            if isinstance(key, str):
                seen.add(key)
            _check_duplicate_keys(value_node)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _check_duplicate_keys(item)


def load_yaml(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    node = yaml.compose(text, Loader=yaml.SafeLoader)
    if node is not None:
        _check_duplicate_keys(node)
    return yaml.safe_load(text)


def branch_issue(branch: str | None) -> int | None:
    match = BRANCH_ISSUE.match(branch or "")
    return int(match.group(1)) if match else None


def adr_number(adr_id: str) -> int | None:
    match = LEGACY_ID.match(adr_id) or RECORD_ID.match(adr_id)
    return int(match.group(1)) if match else None


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def load_legacy(root: Path, errors: list[str]) -> dict[str, dict[str, Any]]:
    """Return the legacy ADRs keyed by ID, recording any problems in ``errors``."""
    path = root / LEGACY_FILE
    if not path.exists():
        return {}
    try:
        data = load_yaml(path) or {}
    except (DuplicateKeyError, yaml.YAMLError) as exc:
        errors.append(f"{LEGACY_FILE}: {exc}; every ADR ID must be unique")
        return {}
    decisions = data.get("decisions") if isinstance(data, dict) else None
    if not isinstance(decisions, dict):
        errors.append(f"{LEGACY_FILE}: expected a 'decisions' mapping keyed by ADR ID")
        return {}
    for adr_id in decisions:
        match = LEGACY_ID.match(str(adr_id))
        if not match or int(match.group(1)) > LEGACY_LAST:
            errors.append(
                f"{LEGACY_FILE}: {adr_id} is a new entry, but this file is closed to "
                f"new ADRs; move it to {RECORDS_DIR}/ADR-<issue>.yaml ({DOCS_POINTER})"
            )
    return {str(k): v for k, v in decisions.items() if isinstance(v, dict)}


def load_records(root: Path, errors: list[str]) -> dict[str, dict[str, Any]]:
    """Return the issue-keyed ADRs keyed by ID, recording any problems in ``errors``."""
    directory = root / RECORDS_DIR
    if not directory.is_dir():
        return {}
    records: dict[str, dict[str, Any]] = {}
    for path in sorted(directory.iterdir()):
        rel = RECORDS_DIR / path.name
        match = RECORD_FILE.match(path.name)
        if not match:
            errors.append(
                f"{rel}: ADR files are named ADR-<issue>.yaml with no zero padding "
                "(for example ADR-483.yaml)"
            )
            continue
        if int(match.group(1)) < ISSUE_KEYED_FLOOR:
            errors.append(
                f"{rel}: issue-keyed ADR numbers start at {ISSUE_KEYED_FLOOR}; "
                f"use the number of the issue this PR closes"
            )
            continue
        try:
            body = load_yaml(path)
        except (DuplicateKeyError, yaml.YAMLError) as exc:
            errors.append(f"{rel}: {exc}")
            continue
        if not isinstance(body, dict):
            errors.append(f"{rel}: expected a mapping of ADR fields")
            continue
        expected_id = path.stem
        if body.get("id") != expected_id:
            errors.append(f"{rel}: 'id' must be {expected_id} to match the file name")
        records[expected_id] = body
    return records


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


def field_errors(adr_id: str, body: dict[str, Any], where: str) -> list[str]:
    """Required-field checks matching the AICaC decisions schema."""
    errors = []
    for field, minimum in REQUIRED_TEXT.items():
        value = body.get(field)
        if not isinstance(value, str) or len(value.strip()) < minimum:
            errors.append(f"{where}: '{field}' is required (at least {minimum} characters)")
    if body.get("status") not in STATUSES:
        errors.append(f"{where}: 'status' must be one of {', '.join(STATUSES)}")
    return errors


def reference_errors(
    legacy: dict[str, dict[str, Any]],
    records: dict[str, dict[str, Any]],
    components: set[str],
) -> list[str]:
    """Check component and ADR references resolve."""
    errors = []
    known = set(legacy) | set(records)
    for adr_id, body in legacy.items():
        successor = body.get("superseded_by")
        if successor and successor not in legacy and successor in records:
            errors.append(
                f"{LEGACY_FILE}: {adr_id}.superseded_by points at {successor}, which the AICaC "
                f"validator can't resolve; list {adr_id} under 'supersedes' in "
                f"{RECORDS_DIR}/{successor}.yaml instead"
            )
    for adr_id, body in records.items():
        where = f"{RECORDS_DIR}/{adr_id}.yaml"
        for component in body.get("affects_components") or []:
            if components and component not in components:
                errors.append(f"{where}: affects_components names unknown component '{component}'")
        refs = list(body.get("supersedes") or [])
        if body.get("superseded_by"):
            refs.append(body["superseded_by"])
        errors.extend(
            f"{where}: references unknown ADR '{ref}'" for ref in refs if ref not in known
        )
    return errors


def duplicate_errors(ids: list[str]) -> list[str]:
    """Two IDs that resolve to the same number (ADR-044 and ADR-44) are duplicates."""
    by_number: dict[int, list[str]] = {}
    for adr_id in ids:
        number = adr_number(adr_id)
        if number is not None:
            by_number.setdefault(number, []).append(adr_id)
    return [
        f"ADR number {number} is used more than once ({', '.join(sorted(names))})"
        for number, names in sorted(by_number.items())
        if len(names) > 1
    ]


def branch_errors(added: list[str], branch: str) -> tuple[list[str], list[str]]:
    """Return (errors, warnings) for the ADR files a PR adds."""
    issue = branch_issue(branch)
    new_adrs = [p for p in added if Path(p).parent == RECORDS_DIR]
    if issue is None:
        if not new_adrs:
            return [], [
                f"branch '{branch}' has no issue number; name it {BRANCH_FORMAT} ({DOCS_POINTER})"
            ]
        return [
            f"{path}: a PR that adds an ADR needs a branch named {BRANCH_FORMAT} "
            f"(got '{branch}'); push a new branch and open a new PR ({DOCS_POINTER})"
            for path in new_adrs
        ], []
    expected = f"{RECORDS_DIR}/ADR-{issue}.yaml"
    return [
        f"{path}: this branch is for issue #{issue}, so its ADR must be {expected}"
        for path in new_adrs
        if path != expected
    ], []


def added_paths(root: Path, base: str) -> list[str]:
    """Paths under .ai/decisions/ that HEAD adds or renames in, relative to ``base``."""
    result = subprocess.run(  # noqa: S603 — fixed argv, no shell
        ["git", "diff", "--name-only", "--diff-filter=AR", base, "HEAD", "--", str(RECORDS_DIR)],
        cwd=root, capture_output=True, text=True, check=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def run_check(root: Path, branch: str | None, base: str | None) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    legacy = load_legacy(root, errors)
    records = load_records(root, errors)
    for adr_id, body in records.items():
        errors.extend(field_errors(adr_id, body, f"{RECORDS_DIR}/{adr_id}.yaml"))
    errors.extend(duplicate_errors([*legacy, *records]))
    errors.extend(reference_errors(legacy, records, _component_ids(root)))
    if branch:
        added = added_paths(root, base) if base else []
        branch_errs, branch_warns = branch_errors(added, branch)
        errors.extend(branch_errs)
        warnings.extend(branch_warns)
    return errors, warnings


def _component_ids(root: Path) -> set[str]:
    path = root / ARCHITECTURE_FILE
    if not path.exists():
        return set()
    components = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("components")
    return set(components) if isinstance(components, dict) else set()


# --------------------------------------------------------------------------
# Index and scaffold
# --------------------------------------------------------------------------


def build_index(root: Path) -> list[dict[str, Any]]:
    """Every ADR from both stores, sorted by number, with its source path."""
    ignored: list[str] = []
    legacy = load_legacy(root, ignored)
    records = load_records(root, ignored)
    superseded_by = {
        old: adr_id for adr_id, body in records.items() for old in body.get("supersedes") or []
    }
    rows = []
    for source, store in ((str(LEGACY_FILE), legacy), (str(RECORDS_DIR), records)):
        for adr_id, body in store.items():
            path = source if store is legacy else f"{source}/{adr_id}.yaml"
            rows.append({
                "id": adr_id,
                "title": str(body.get("title", "")),
                "status": str(body.get("status", "")),
                "superseded_by": body.get("superseded_by") or superseded_by.get(adr_id),
                "source": path,
            })
    return sorted(rows, key=lambda row: adr_number(row["id"]) or 0)


def skeleton(issue: int, title: str, today: datetime.date) -> str:
    return (
        f"id: ADR-{issue}\n"
        f"title: {json.dumps(title)}\n"
        f"date: '{today.isoformat()}'\n"
        "status: proposed\n"
        "context: |-\n  What problem made this decision necessary?\n"
        "decision: |-\n  What we decided, in a few short paragraphs or bullets.\n"
        "alternatives_considered:\n- name: Another option\n  rejected_because: Why not.\n"
        "consequences:\n  positive:\n  - What gets better.\n  negative:\n  - What it costs.\n"
    )


def current_branch(root: Path) -> str:
    result = subprocess.run(  # noqa: S603 — fixed argv, no shell
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=root, capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _report(kind: str, message: str) -> None:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{kind}::{message}")
    else:
        print(f"{kind}: {message}", file=sys.stderr)


def _cmd_check(args: argparse.Namespace) -> int:
    errors, warnings = run_check(args.repo_root, args.branch, args.base)
    for message in warnings:
        _report("warning", message)
    for message in errors:
        _report("error", message)
    if errors:
        return 1
    print("ADR records OK")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    rows = build_index(args.repo_root)
    if args.format == "json":
        print(json.dumps(rows, indent=2))
    elif args.format == "yaml":
        print(yaml.safe_dump(rows, sort_keys=False, allow_unicode=True), end="")
    else:
        for row in rows:
            note = f" (superseded by {row['superseded_by']})" if row["superseded_by"] else ""
            print(f"{row['id']:<9} {row['status']:<11} {row['title']}{note}")
    return 0


def _cmd_new(args: argparse.Namespace) -> int:
    root: Path = args.repo_root
    issue = args.issue or branch_issue(current_branch(root))
    if issue is None:
        _report("error", f"no issue number; pass --issue or use a branch named {BRANCH_FORMAT}")
        return 1
    target = root / RECORDS_DIR / f"ADR-{issue}.yaml"
    if target.exists():
        _report("error", f"{target.relative_to(root)} already exists")
        return 1
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(skeleton(issue, args.title, datetime.date.today()), encoding="utf-8")
    print(f"Wrote {target.relative_to(root)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="validate both ADR stores")
    check.add_argument("--branch", default="", help="PR head branch; omit on pushes")
    check.add_argument("--base", default="", help="commit the PR merges into (e.g. HEAD^1)")
    check.set_defaults(func=_cmd_check)

    listing = sub.add_parser("list", help="print every ADR, sorted by number")
    listing.add_argument("--format", choices=("table", "yaml", "json"), default="table")
    listing.set_defaults(func=_cmd_list)

    new = sub.add_parser("new", help="scaffold .ai/decisions/ADR-<issue>.yaml")
    new.add_argument("--issue", type=int, default=None, help="default: from the branch name")
    new.add_argument("--title", default="Short decision title")
    new.set_defaults(func=_cmd_new)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
