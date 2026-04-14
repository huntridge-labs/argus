#!/usr/bin/env python3
"""Check that docs/cli-reference.md is up to date with the CLI parser.

Regenerates the CLI docs from argparse and compares against the committed
file, ignoring the date line (which changes daily). Exits non-zero if
the docs are stale.

Usage:
    python -m scripts.ci.check_cli_docs          # check only
    python -m scripts.ci.check_cli_docs --fix    # regenerate in place
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
DOCS_PATH = REPO_ROOT / "docs" / "cli-reference.md"

# Ensure argus is importable
sys.path.insert(0, str(REPO_ROOT))


def _strip_volatile_lines(text: str) -> str:
    """Remove lines that change on every generation (date, version)."""
    lines = []
    for line in text.splitlines():
        # Skip the auto-generated date line
        if line.startswith("> Auto-generated from argparse definitions on"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _generate_quiet() -> str:
    """Generate CLI docs without printing to stdout."""
    import io
    from scripts.ci.gen_cli_docs import generate_cli_docs

    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        return generate_cli_docs()
    finally:
        sys.stdout = old_stdout


def main() -> int:
    fix_mode = "--fix" in sys.argv

    generated = _generate_quiet()

    if fix_mode:
        DOCS_PATH.write_text(generated, encoding="utf-8")
        print(f"Updated {DOCS_PATH}")
        return 0

    if not DOCS_PATH.exists():
        print(f"ERROR: {DOCS_PATH} does not exist.")
        print("Run: python -m scripts.ci.check_cli_docs --fix")
        return 1

    committed = DOCS_PATH.read_text(encoding="utf-8")

    if _strip_volatile_lines(generated) != _strip_volatile_lines(committed):
        print(f"ERROR: {DOCS_PATH} is out of date with the CLI parser.")
        print("Run: python -m scripts.ci.check_cli_docs --fix")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
