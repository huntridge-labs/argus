"""Runtime shim for the architecture-map view-model transformer.

The canonical implementation lives at ``scripts/docsite/architecture.py``
because the transformer follows the docsite-tooling patterns (see the
``scripts/docsite/builder.py`` / ``scripts/docsite/parsers.py`` style).
``scripts/docsite/`` isn't a Python package distributed in the
``argus-security`` wheel, though, so the runtime consumers (the
FastAPI ``/architecture`` route and the MCP ``argus://architecture``
resource) can't import it the normal way.

This shim resolves that by locating the file on disk relative to the
installed argus package and loading it via ``importlib.util``. In
editable-install workflows (``pip install -e .``) it just works.
In a clean wheel install with no source checkout, the load fails
fast and the caller surfaces an actionable error message rather than
a confusing ``ModuleNotFoundError`` deep in the stack.

Public surface is the same as the canonical module — anything
exported there is re-exported here. Update the ``_EXPORTS`` list if
the canonical surface grows.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


# Re-export list — keep in sync with scripts/docsite/architecture.py.
_EXPORTS = (
    "SCHEMA_VERSION",
    "Registries",
    "introspect_registries",
    "load_inputs",
    "build_view_model",
    "build_view_model_from_repo",
    "COLUMNS",
)


def _find_canonical() -> Path | None:
    """Locate ``scripts/docsite/architecture.py`` on disk.

    Walks up from this file (the argus package) looking for the
    docsite scripts directory. Editable installs put the argus
    package next to the ``scripts/`` directory; wheel installs
    don't, but those are out of scope for this resolver.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "scripts" / "docsite" / "architecture.py"
        if candidate.is_file():
            return candidate
    return None


def _load_canonical() -> Any:
    """Import the canonical module via importlib.util.

    Returns the module object. Raises ``ImportError`` with an
    actionable message when the file can't be found — typical cause
    is a wheel install without a repo checkout for the SDK
    introspection inputs.
    """
    cached = sys.modules.get("argus._architecture_canonical")
    if cached is not None:
        return cached
    path = _find_canonical()
    if path is None:
        raise ImportError(
            "Architecture-map transformer not found. Expected "
            "``scripts/docsite/architecture.py`` next to the argus "
            "package. Install argus in editable mode "
            "(``pip install -e .`` from the argus repo root) or "
            "make the repo checkout available on disk."
        )
    spec = importlib.util.spec_from_file_location(
        "argus._architecture_canonical", path,
    )
    if spec is None or spec.loader is None:  # pragma: no cover — defensive
        raise ImportError(f"Cannot build module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["argus._architecture_canonical"] = module
    spec.loader.exec_module(module)
    return module


def __getattr__(name: str) -> Any:
    """Lazily forward attribute lookups to the canonical module.

    PEP 562 module-level ``__getattr__`` keeps the import cheap (the
    canonical file isn't loaded until something actually asks for an
    export). Anything not in ``_EXPORTS`` raises ``AttributeError``
    so typos surface immediately.
    """
    if name not in _EXPORTS:
        raise AttributeError(f"module 'argus.architecture_map' has no attribute {name!r}")
    module = _load_canonical()
    return getattr(module, name)


def __dir__() -> list[str]:  # pragma: no cover — IDE / repl niceties
    return list(_EXPORTS)
