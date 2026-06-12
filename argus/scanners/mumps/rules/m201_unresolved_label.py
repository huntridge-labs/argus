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

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule
from ._common import is_command_mnemonic, is_objectscript, preceded_by_error

# A MUMPS label occupies column 0 (code lines are always indented). Match the
# leading label token on each line directly from source: the grammar does NOT
# reliably emit a *parameterized* entry label (``WARNING(A,B)``) as a ``label``
# node, so a purely structural collector misses them and every caller FPs.
# Bytes regex over source_bytes avoids a decode of the whole file.
_LABEL_LINE_RE = re.compile(rb"^(%?[A-Za-z][A-Za-z0-9]*|[0-9]+)", re.MULTILINE)
# A real DO/GOTO label target is a bare label identifier (optionally numeric).
# Anything else (``I $E``, ``X Y``) is a grammar misparse, not a reference.
_VALID_LABEL_RE = re.compile(r"^(%?[A-Za-z][A-Za-z0-9]*|[0-9]+)$")


def _collect_declared_labels(parsed: ParsedSource) -> set[str]:
    """Return the set of label names declared anywhere in the file
    (uppercased for case-insensitive comparison)."""
    names: set[str] = set()
    for node in walk(parsed.tree.root_node):
        if node.type != "label":
            continue
        text = parsed.node_text(node).strip()
        # The label node sometimes wraps a comment; isolate the first
        # whitespace-delimited token, then strip a parenthesized formal-arg
        # list (``RUN(A,B)`` declares label ``RUN``).
        first_token = text.split(None, 1)[0] if text else ""
        first_token = first_token.split("(", 1)[0]
        if first_token:
            names.add(first_token.upper())
    # Text fallback: every column-0 label token, including the parameterized
    # entries and final-block labels the grammar drops from the label-node
    # set. This is what makes the declared set complete enough for default-on.
    for match in _LABEL_LINE_RE.finditer(parsed.source_bytes):
        names.add(match.group(1).decode("ascii", errors="replace").upper())
    return names


def _project_labels(config: dict | None) -> set[str]:
    """All label and routine names known across the scanned project, from
    the cross-file call graph (``config['_callgraph']``), cached on config.

    A bare ``D FOO`` that resolves to a label or routine somewhere in the
    project is almost always a grammar mis-extraction of an intra-file label
    or a cross-routine call whose ``^ROUTINE`` the parser dropped — not a
    genuine undefined-label crash. Demoting those (vs. the old intra-file-only
    view) is what makes M201 trustworthy at scale; a label that resolves
    NOWHERE in the project stays a high-confidence finding. Empty for
    single-file scans (no call graph), where the rule stays intra-file."""
    cg = (config or {}).get("_callgraph")
    if cg is None:
        return set()
    cached = config.get("_m201_project_labels")
    if cached is not None:
        return cached
    labels: set[str] = set(cg.routines)
    for routine in cg.routines.values():
        labels |= set(routine.labels)
    config["_m201_project_labels"] = labels
    return labels


class UnresolvedLabelRule(Rule):
    id = "M201"
    severity = Severity.INFO
    title = "DO / GOTO to undeclared label"
    cwe = None  # diagnostic

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        # ObjectScript dot-method syntax (``config.Method()``, ``DUZ``) is
        # not VistA-M label dispatch; the grammar mangles it into phantom
        # ``routine_call`` targets. Skip such files rather than emit FPs.
        if is_objectscript(parsed.source_bytes):
            return
        declared = _collect_declared_labels(parsed)
        project = _project_labels(config)
        source = parsed.source_bytes
        for node in walk(parsed.tree.root_node):
            if node.type != "routine_call":
                continue
            # A genuine ``D LABEL`` / ``G LABEL`` is preceded by whitespace
            # (after the command). When the byte before the call node is a
            # letter or ``.``, the call is a grammar fragment of a larger
            # token — an ObjectScript ``obj.Property`` or a mid-token
            # misparse — not a real label reference.
            if node.start_byte > 0:
                prev = source[node.start_byte - 1:node.start_byte]
                if prev.isalpha() or prev == b".":
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
            if not label or not _VALID_LABEL_RE.match(label):
                continue
            # Resolves in this file, or anywhere in the project (a label /
            # routine name the call graph knows) — not an undefined-label
            # crash. Only a label that resolves nowhere is reported.
            if label in declared or label in project:
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
