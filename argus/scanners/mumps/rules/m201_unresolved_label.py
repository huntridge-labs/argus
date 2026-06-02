"""M201 — DO / GOTO to a label that doesn't exist in this file (diagnostic).

``D MISSING`` (or ``G MISSING``) where ``MISSING`` is neither declared
in the current routine nor reachable via a cross-routine ``^ROUTINE``
reference is dead code that crashes at runtime. mHawk surfaces this as
a diagnostic; we match the behaviour at INFO severity.

Scope: intra-file only. A bare label reference (no ``^ROUTINE``
suffix) must resolve against the labels declared in *this* file.
Cross-routine references (``LABEL^OTHER``, ``^OTHER``) are left alone
because we don't have a project-wide routine index — that's Phase 2
inter-procedural work.

Detection:

1. Collect declared label names by walking ``routine_definition`` →
   ``label`` first-child.
2. Walk for ``routine_call`` nodes; for each, isolate the label
   portion (before any ``^``) and skip if a ``^`` is present (cross-
   routine — out of scope).
3. If the label name is non-empty and not in the declared set, flag.
"""

from __future__ import annotations

from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule
from ._common import is_command_mnemonic, is_objectscript, preceded_by_error


def _collect_declared_labels(parsed: ParsedSource) -> set[str]:
    """Return the set of label names declared anywhere in the file
    (uppercased for case-insensitive comparison)."""
    names: set[str] = set()
    for node in walk(parsed.tree.root_node):
        if node.type != "label":
            continue
        text = parsed.node_text(node).strip()
        # The label node sometimes wraps a comment; isolate the first
        # whitespace-delimited token, which is the label name itself.
        first_token = text.split(None, 1)[0] if text else ""
        if first_token:
            names.add(first_token.upper())
    return names


class UnresolvedLabelRule(Rule):
    id = "M201"
    severity = Severity.INFO
    title = "DO / GOTO to undeclared label"
    cwe = None  # diagnostic
    # Off by default: FP-dominant at scale. The declared-labels extractor
    # drops labels whose bodies contain heavy quote-escaping and the final
    # label block, so legitimate intra-file forward references read as
    # undeclared; misparses (ObjectScript ``.Property`` dot-syntax becoming a
    # phantom ``GOTO``, the command token after an argumentless ``D ``) also
    # surface as phantom DO/GOTO targets. Re-enabling on by default awaits an
    # extractor + misparse-guard rewrite. Opt in via
    # ``scanners.mumps.rules.M201.enabled: true``.
    enabled_by_default = False

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        # ObjectScript dot-method syntax (``config.Method()``, ``DUZ``) is
        # not VistA-M label dispatch; the grammar mangles it into phantom
        # ``routine_call`` targets. Skip such files rather than emit FPs.
        if is_objectscript(parsed.source_bytes):
            return
        declared = _collect_declared_labels(parsed)
        for node in walk(parsed.tree.root_node):
            if node.type != "routine_call":
                continue
            text = parsed.node_text(node).strip()
            # Skip cross-routine references (``LABEL^ROUTINE`` or
            # ``^ROUTINE``); we can't resolve those without a
            # project-wide index. Phase 2 inter-procedural work.
            if "^" in text:
                continue
            # Skip indirection (``@VAR``); that's M002 / M005 territory.
            if text.startswith("@"):
                continue
            # Grammar-misparse guards (the bulk of this rule's false
            # positives on real corpora):
            #  - a bare command keyword the grammar emitted as a call
            #    target (``DTIME`` in ``R X:DTIME`` splits to ``D``+``TIME``);
            #  - any call adjacent to an ERROR node, the signature of a
            #    line the grammar couldn't parse (read-timeouts,
            #    postconditionals).
            if is_command_mnemonic(text):
                continue
            if preceded_by_error(node):
                continue
            # Trim any opening paren (``LABEL(arg)``) before lookup
            label = text.split("(", 1)[0].strip().upper()
            if not label:
                continue
            if label in declared:
                continue
            yield self.make_finding(
                parsed,
                node,
                description=(
                    f"DO / GOTO references label '{label}' which is not "
                    "declared in this file. At runtime the dispatch raises "
                    "an undefined-label error. If the label lives in "
                    "another routine, qualify the call with ^ROUTINE."
                ),
                metadata={
                    "label": label,
                    "declared_labels": sorted(declared),
                },
            )
