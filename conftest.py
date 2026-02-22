"""
Root conftest.py — force-imports all action scripts for coverage measurement.

Coverage.py only measures files that are actually imported during the test run.
Since action scripts live outside Python packages (no __init__.py), scripts
without a corresponding test file are invisible to coverage and silently
excluded from the coverage threshold.

This conftest walks .github/actions/*/scripts/ at collection time and imports
every .py file it finds, ensuring untested scripts appear at 0% and count
against the 80% minimum.
"""

import importlib.util
import sys
import warnings
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
ACTIONS_DIR = REPO_ROOT / ".github" / "actions"


def _import_script(path: Path) -> bool:
    """Import a standalone script so coverage.py can measure it."""
    module_name = f"_cov_import_.{path.parent.parent.name}.{path.stem}"
    if module_name in sys.modules:
        return True
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            return True
    except Exception as exc:
        warnings.warn(
            f"conftest: failed to import {path.relative_to(REPO_ROOT)} "
            f"for coverage — {type(exc).__name__}: {exc}",
            stacklevel=1,
        )
    return False


def pytest_configure(config):
    """Import all action scripts before test collection begins."""
    if not ACTIONS_DIR.is_dir():
        return

    imported = 0
    failed = 0

    for scripts_dir in sorted(ACTIONS_DIR.glob("*/scripts")):
        for py_file in sorted(scripts_dir.glob("*.py")):
            if _import_script(py_file):
                imported += 1
            else:
                failed += 1

    if failed:
        warnings.warn(
            f"conftest: {failed} script(s) failed to import for coverage "
            f"(see warnings above). These files will be invisible to coverage.",
            stacklevel=1,
        )
