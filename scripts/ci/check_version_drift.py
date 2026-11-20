"""Fail CI when a release-it-managed version reference disagrees with version.yaml.

``check_version_refs`` makes sure every version reference has a release-it
rule. This check makes sure what those rules currently match is the version
in ``version.yaml``. A hand edit, a bad merge, or a rule that broke for one
release and was fixed later can each leave a file on an older version
without either check noticing (``.ai/context.yaml`` sat at 1.4.1 while the
package shipped 1.15.0; see #557).

Only rules whose ``replace`` writes ``{{version}}`` are checked. Rules that
write something else (an image digest, a branch name) aren't version refs.

Run as:
    python -m scripts.ci.check_version_drift
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

RELEASE_IT_FILE = Path(".release-it.json")
VERSION_FILE = Path("version.yaml")
VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
# JavaScript regex flags that change what a pattern matches.
_JS_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}


def current_version(root: Path) -> str:
    """The version release-it last wrote, from the first token of version.yaml."""
    text = (root / VERSION_FILE).read_text(encoding="utf-8")
    match = VERSION.match(text.strip())
    if not match:
        raise ValueError(f"{VERSION_FILE} does not start with a version")
    return match.group(0)


def _bumper_rules(node: Any) -> Iterator[dict[str, Any]]:
    """Yield every regex-bumper ``out`` entry, wherever it sits in the config."""
    if isinstance(node, dict):
        if "files" in node and "search" in node:
            yield node
        for value in node.values():
            yield from _bumper_rules(value)
    elif isinstance(node, list):
        for value in node:
            yield from _bumper_rules(value)


def version_rules(root: Path) -> list[dict[str, Any]]:
    """The rules that write ``{{version}}``, with their compiled pattern."""
    config = json.loads((root / RELEASE_IT_FILE).read_text(encoding="utf-8"))
    rules = []
    for rule in _bumper_rules(config):
        if "{{version}}" not in str(rule.get("replace", "")):
            continue
        search = rule["search"]
        pattern = search.get("pattern") if isinstance(search, dict) else search
        flags = 0
        for flag in (search.get("flags") or "") if isinstance(search, dict) else "":
            flags |= _JS_FLAGS.get(flag, 0)
        try:
            compiled = re.compile(pattern, flags)
        except re.error as exc:
            # check_version_refs already warns about patterns Python can't read.
            print(f"WARNING: skipping rule {pattern!r} ({exc})", file=sys.stderr)
            continue
        files = rule["files"] if isinstance(rule["files"], list) else [rule["files"]]
        rules.append({"pattern": compiled, "files": files})
    return rules


def find_drift(root: Path, version: str, rules: list[dict[str, Any]]) -> list[str]:
    """Return ``path:line: found X`` for every matched version that isn't ``version``."""
    drift = []
    for rule in rules:
        paths = sorted({p for glob in rule["files"] for p in root.glob(glob) if p.is_file()})
        for path in paths:
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in rule["pattern"].finditer(text):
                for found in VERSION.findall(match.group(0)):
                    if found != version:
                        line = text.count("\n", 0, match.start()) + 1
                        rel = path.relative_to(root).as_posix()
                        drift.append(f"{rel}:{line}: found {found}")
    return sorted(set(drift))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root", type=Path, default=Path("."),
        help="repo root containing .release-it.json and version.yaml (default: cwd)",
    )
    args = parser.parse_args(argv)
    root: Path = args.repo_root.resolve()

    try:
        version = current_version(root)
        rules = version_rules(root)
    except (OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    drift = find_drift(root, version, rules)
    if drift:
        print(f"ERROR: these version references don't match {VERSION_FILE} ({version}):",
              file=sys.stderr)
        for line in drift:
            print(f"  {line}", file=sys.stderr)
        print("Set them back to the current version. release-it moves them all on the "
              "next release, so never bump them by hand.", file=sys.stderr)
        return 1

    print(f"All release-it version references match {version}.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
