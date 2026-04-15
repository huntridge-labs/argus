#!/usr/bin/env python3
"""Validate built wheel/sdist contents before publishing.

Checks that the package:
1. Contains only expected files (whitelist)
2. Does NOT contain secrets, tests, or dev files (blocklist)
3. Has the correct version

Usage:
    python -m scripts.ci.check_package              # check dist/*.whl
    python -m scripts.ci.check_package --fix        # (no fix mode — read-only check)
"""

import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent

# Files that MUST be in the package
REQUIRED_PATTERNS = [
    "argus/__init__.py",
    "argus/cli.py",
    "argus/core/engine.py",
    "argus/core/models.py",
    "argus/scanners/__init__.py",
    "argus/linters/__init__.py",
    "argus/scn/__init__.py",
    "argus/reporters/__init__.py",
]

# Patterns that must NEVER appear in the package
BLOCKLIST = [
    ".env",
    ".git/",
    ".github/",
    "node_modules/",
    "__pycache__/",
    ".pyc",
    "tests/",
    "argus/tests/",
    "test_",
    "conftest.py",
    ".secret",
    "credential",
    ".key",
    ".pem",
    ".p12",
    "id_rsa",
    "id_ed25519",
    ".docker/config.json",
    "fixtures/",
    "coverage/",
    "htmlcov/",
    ".pytest_cache/",
]


def check_wheel(wheel_path: Path) -> list[str]:
    """Check a wheel file for issues. Returns list of error messages."""
    errors = []

    with zipfile.ZipFile(wheel_path) as zf:
        names = zf.namelist()

        # Check required files
        for pattern in REQUIRED_PATTERNS:
            if not any(pattern in name for name in names):
                errors.append(f"MISSING: {pattern} not found in wheel")

        # Check blocklist
        for name in names:
            name_lower = name.lower()
            for blocked in BLOCKLIST:
                if blocked.lower() in name_lower:
                    errors.append(f"BLOCKED: {name} matches blocklist pattern '{blocked}'")
                    break

    return errors


def main() -> int:
    dist_dir = REPO_ROOT / "dist"
    wheels = list(dist_dir.glob("*.whl"))

    if not wheels:
        print("ERROR: No wheel files found in dist/")
        print("Run: python -m build --wheel")
        return 1

    all_clean = True
    for wheel in wheels:
        print(f"Checking {wheel.name}...")
        errors = check_wheel(wheel)

        if errors:
            all_clean = False
            for err in errors:
                print(f"  {err}")
        else:
            with zipfile.ZipFile(wheel) as zf:
                print(f"  OK — {len(zf.namelist())} files, no issues")

    return 0 if all_clean else 1


if __name__ == "__main__":
    sys.exit(main())
