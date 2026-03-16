"""CLI entry point — ``python -m docsite`` from the scripts/ directory."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .builder import build
from .validator import validate


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Argus docs site")
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parent.parent.parent),
        help="Path to Argus repo root (default: grandparent of docsite/)",
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parent.parent.parent / "site-build"),
        help="Output directory for mkdocs project (default: <repo>/site-build)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate docsite.yml and .docsite.yml files, then exit",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    output_dir = Path(args.output_dir).resolve()

    if not (repo_root / ".github").exists():
        print(f"❌ {repo_root} doesn't look like the Argus repo (.github not found)")
        sys.exit(1)

    if args.validate:
        valid = validate(repo_root)
        sys.exit(0 if valid else 1)

    build(repo_root, output_dir)


if __name__ == "__main__":
    main()
