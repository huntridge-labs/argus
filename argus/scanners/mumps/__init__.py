"""MUMPS / M language SAST scanner.

Public surface: ``MumpsScanner``. Rule implementations live in
``argus.scanners.mumps.rules.*`` and are registered through
``argus.scanners.mumps.rules.RULES``. The tree-sitter wrapper sits in
``argus.scanners.mumps.parser`` and is import-guarded so the package can be
imported even when ``py-tree-sitter`` or the compiled grammar are not
installed (``is_available()`` resolves that gate at scan time).
"""

from .scanner import MumpsScanner

__all__ = ["MumpsScanner"]
