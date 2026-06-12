"""Tree-sitter wrapper for the MUMPS grammar.

The grammar (``janus-llm/tree-sitter-mumps``, Apache-2.0, MITRE Public
Release 23-4084) is not on PyPI. We support two install paths:

1. **Container execution.** The ``scanner-mumps`` image (built by
   ``docker/Dockerfile.mumps``) compiles ``mumps.so`` at image build time and
   places it at ``/opt/argus/grammars/mumps.so``. The scanner inside the
   container loads it from there.

2. **Local execution.** Developers who already have ``py-tree-sitter``
   installed can run ``scripts/build-mumps-grammar.sh`` to compile the
   grammar into ``~/.cache/argus/grammars/mumps.so``. The scanner picks
   it up automatically.

The override hook ``ARGUS_MUMPS_GRAMMAR`` lets CI pin a known-good build.

All ``tree_sitter`` imports are deferred so ``argus`` can be imported
on systems that do not have py-tree-sitter installed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


GRAMMAR_ENV_VAR = "ARGUS_MUMPS_GRAMMAR"

_DEFAULT_GRAMMAR_PATHS = (
    "/opt/argus/grammars/mumps.so",
    "~/.cache/argus/grammars/mumps.so",
)


def grammar_search_paths() -> list[Path]:
    """Return the ordered grammar lookup paths."""
    paths: list[Path] = []
    env = os.environ.get(GRAMMAR_ENV_VAR, "").strip()
    if env:
        paths.append(Path(env).expanduser())
    paths.extend(Path(p).expanduser() for p in _DEFAULT_GRAMMAR_PATHS)
    return paths


def find_grammar() -> Optional[Path]:
    """Locate the compiled MUMPS grammar shared library, or return None."""
    for candidate in grammar_search_paths():
        if candidate.is_file():
            return candidate
    return None


def tree_sitter_available() -> bool:
    """Return True if both ``py-tree-sitter`` and the grammar are installed."""
    try:
        import tree_sitter  # noqa: F401
    except ImportError:
        return False
    return find_grammar() is not None


@dataclass(frozen=True)
class ParsedSource:
    """A parsed MUMPS source file.

    ``tree`` is opaque (a ``tree_sitter.Tree``) to keep this module free
    of a hard import dependency. Rule implementations treat it as a
    handle and call helpers in this module to walk it.
    """

    path: Path
    source_bytes: bytes
    tree: Any

    @property
    def source_text(self) -> str:
        return self.source_bytes.decode("utf-8", errors="replace")

    def node_text(self, node: Any) -> str:
        """Decode the source slice covered by ``node``."""
        return self.source_bytes[node.start_byte:node.end_byte].decode(
            "utf-8", errors="replace",
        )

    def location(self, node: Any) -> str:
        """Return ``path:line[:col]`` for a tree-sitter node (1-indexed line)."""
        line = node.start_point[0] + 1
        col = node.start_point[1] + 1
        return f"{self.path}:{line}:{col}"


def _tree_sitter_minor() -> tuple[int, int]:
    """(major, minor) of the installed py-tree-sitter binding."""
    from importlib.metadata import version
    parts = version("tree-sitter").split(".")
    return int(parts[0]), int(parts[1])


def _grammar_capsule(grammar: Path):
    """Return a ``tree_sitter.Language`` PyCapsule for the compiled grammar.

    The grammar shared library exports ``tree_sitter_mumps()`` returning a
    ``const TSLanguage *``; py-tree-sitter >= 0.22 wants that pointer wrapped
    in a PyCapsule named ``tree_sitter.Language`` rather than a path + name.
    """
    import ctypes
    lib = ctypes.cdll.LoadLibrary(str(grammar))
    lib.tree_sitter_mumps.restype = ctypes.c_void_p
    new_capsule = ctypes.pythonapi.PyCapsule_New
    new_capsule.restype = ctypes.py_object
    new_capsule.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
    return new_capsule(lib.tree_sitter_mumps(), b"tree_sitter.Language", None)


def _load_grammar(grammar: Path):
    """Load the compiled MUMPS grammar; return ``(Language, Parser)``.

    py-tree-sitter changed its API at 0.22: the two-argument
    ``Language(path, name)`` was replaced by ``Language(<pointer>)`` and the
    language now goes to the ``Parser`` constructor instead of
    ``set_language``. We support both so the ``[mumps]`` extra works across
    the 0.20–0.25 range without forcing a binding version (#248). The
    compiled grammar (ABI 14) is accepted by both.
    """
    from tree_sitter import Language, Parser
    if _tree_sitter_minor() >= (0, 22):
        language = Language(_grammar_capsule(grammar))
        return language, Parser(language)
    # Pre-0.22 two-argument API.
    language = Language(str(grammar), "mumps")
    parser = Parser()
    parser.set_language(language)
    return language, parser


class MumpsParser:
    """Lazy-initialized parser for MUMPS source files.

    Cached at the class level so the grammar shared library is loaded
    exactly once per process even when the scanner is invoked over many
    files. Safe to instantiate eagerly; the grammar load happens on first
    ``parse()`` call.
    """

    _language = None
    _parser = None

    @classmethod
    def _load(cls) -> None:
        if cls._parser is not None:
            return
        try:
            import tree_sitter  # noqa: F401  (availability check only)
        except ImportError as exc:
            raise GrammarUnavailable(
                "py-tree-sitter not installed. Install via "
                "`pip install argus-security[mumps]` or use the scanner-mumps container image.",
            ) from exc
        grammar = find_grammar()
        if grammar is None:
            paths = ", ".join(str(p) for p in grammar_search_paths())
            raise GrammarUnavailable(
                f"MUMPS grammar shared library not found. Searched: {paths}. "
                "Run scripts/build-mumps-grammar.sh or use the scanner-mumps container image.",
            )
        cls._language, cls._parser = _load_grammar(grammar)

    @classmethod
    def parse(cls, path: Path, source_bytes: bytes) -> ParsedSource:
        cls._load()
        tree = cls._parser.parse(source_bytes)
        return ParsedSource(path=path, source_bytes=source_bytes, tree=tree)


class GrammarUnavailable(RuntimeError):
    """Raised when tree-sitter or the compiled MUMPS grammar are missing."""


def walk(node: Any):
    """Depth-first iteration over a tree-sitter subtree."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        # Reversed so children come out in source order under DFS.
        stack.extend(reversed(current.children))
