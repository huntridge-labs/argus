"""MUMPS / M language SAST scanner.

Public surface: ``MScanner``. Rule implementations live in
``argus.scanners.m.rules.*`` and are registered through
``argus.scanners.m.rules.RULES``. The tree-sitter wrapper sits in
``argus.scanners.m.parser`` and is import-guarded so the package can be
imported even when ``py-tree-sitter`` or the compiled grammar are not
installed (``is_available()`` resolves that gate at scan time).
"""

from .scanner import MScanner

__all__ = ["MScanner"]
