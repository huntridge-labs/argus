"""Rule abstraction for the MUMPS scanner.

Each rule subclasses ``Rule`` and implements ``analyze(parsed)``,
returning ``Finding`` instances. The scanner runs every registered rule
against every parsed file; rules are responsible for filtering down to
their own concern.

A rule's ``id`` (``M001``, ``M002``, ...) and ``cwe`` become the
``Finding.id`` / ``Finding.cwe`` fields. The ``severity`` is fixed per
rule for Phase 1; in later phases config will allow overrides via the
``rules.severity`` map in argus.yml.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Optional

from argus.core.models import Finding, Severity
from .parser import ParsedSource


class Rule(ABC):
    """Abstract base for a MUMPS scanner rule.

    Subclasses **must** declare the four class-level attributes
    (``id``, ``severity``, ``title``, ``cwe``) and implement
    ``analyze``. The ``description_template`` is optional; rules that
    interpolate runtime values into the description override
    ``finding_description``.
    """

    id: str = ""
    severity: Severity = Severity.MEDIUM
    title: str = ""
    cwe: Optional[str] = None

    @abstractmethod
    def analyze(
        self,
        parsed: ParsedSource,
        config: Optional[dict] = None,
    ) -> Iterable[Finding]:
        """Yield findings for this rule against ``parsed``.

        ``config`` is the per-scanner config dict (``scanners.m`` block
        in ``argus.yml``). Most rules ignore it; taint-aware rules use
        ``config['taint_sources']`` to extend the recognized source
        surface beyond the built-in READ / $ZARGV / HTTP-global set.
        """

    def make_finding(
        self,
        parsed: ParsedSource,
        node,
        *,
        description: Optional[str] = None,
        metadata: Optional[dict] = None,
        severity: Optional[Severity] = None,
    ) -> Finding:
        """Construct a Finding with rule defaults filled in.

        Subclasses call this to keep finding construction terse and
        consistent. The ``location`` is derived from the tree-sitter
        node's start position. ``severity`` overrides the class-level
        default — used by rules that calibrate severity per finding
        (e.g. M003 bumping to CRITICAL on PIPE-device sites).
        """
        return Finding(
            id=self.id,
            severity=severity or self.severity,
            title=self.title,
            description=description or self.title,
            location=parsed.location(node),
            cwe=self.cwe,
            scanner="mumps",
            metadata=metadata or {},
        )
