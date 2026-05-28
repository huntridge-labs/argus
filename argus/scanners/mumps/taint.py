"""Shared taint-source collection for MUMPS rules.

Multiple rules (``M001`` XECUTE, ``M003`` OPEN/USE, ``M005`` tainted
dispatch) all need the same first pass: walk the parse tree, identify
variables assigned from a tainted source, hand the rule a ``set`` of
uppercased identifier names. Keeping the logic here removes the
near-duplicate keyword regex + identifier extraction copies that
otherwise live inside each rule module.

Phase 1+ taint sources recognized here:

* **READ / R** commands. Every identifier in the argument subtree
  is added to the tainted set. Format specifiers (``!``) and string
  prompts are skipped naturally because they aren't ``local_variable``
  / ``identifier`` nodes.
* **``$ZARGV``** (YottaDB / GT.M process arguments). When an
  ``assignment`` RHS references ``$ZARGV`` in any form
  (``$ZARGV``, ``$ZARGV(1)``, ``$P($ZARGV(2)," ")``) the LHS is
  marked tainted.
* **HTTP context globals.** ``^%CGI(...)``, ``^%REQUEST(...)``, and
  ``^%session(...)`` carry per-request input on legacy VistA web
  stacks. An ``assignment`` whose RHS references one of these
  taints its LHS.

Phase 2 will add formal arguments on entry labels (requires
inter-procedural scope analysis), additional implementation-specific
intrinsics (``$ZIO``, ``$ZQUIT``), and configurable sources via
``argus.yml``. The collector signature is intentionally stable so
adding sources doesn't require rule changes.
"""

from __future__ import annotations

import re

from .parser import ParsedSource, walk


# Anchored to the command's leading token — the grammar elides the
# ``keyword`` child for single-letter READ commands (``R CMD``), so a
# text-anchored match is more reliable than a child_by_field_name lookup.
_READ_KEYWORD_RE = re.compile(r"^\s*R(?:EAD)?\b", re.IGNORECASE)

# Substring patterns we look for inside an assignment RHS to decide
# whether the LHS picks up taint. Whole-word matching keeps unrelated
# locals named ``ZARGV`` or ``CGI`` from misfiring.
_NON_READ_TAINT_PATTERNS = (
    re.compile(r"\$ZARGV\b", re.IGNORECASE),
    re.compile(r"\^%CGI\b"),
    re.compile(r"\^%REQUEST\b"),
    re.compile(r"\^%session\b"),
)


def _argument_node(command_node):
    """Return the arguments subtree for a command, or None."""
    for field_name in ("arguments", "argument", "expression"):
        node = command_node.child_by_field_name(field_name)
        if node is not None:
            return node
    for child in command_node.children:
        if child.type in {"arguments", "argument"}:
            return child
    return None


def _extract_target_identifiers(arg_node) -> list[str]:
    """Identifier tokens that are direct read-targets of ``READ``.

    READ arguments mix format-control characters (``!``, ``#``), prompt
    strings, and target variables. Identifier nodes from the arguments
    subtree are a conservative approximation; false positives here only
    widen the tainted set, never narrow it.
    """
    if arg_node is None:
        return []
    targets: list[str] = []
    for node in walk(arg_node):
        if node.type in {"identifier", "local_variable", "variable"}:
            targets.append(node.text.decode("utf-8", errors="replace").strip())
    return targets


def _named_children(node):
    return [c for c in node.children if c.is_named]


def _assignment_lhs_rhs(assignment_node):
    """Return ``(lhs_node, rhs_node)`` for an ``assignment`` subtree.

    Picks the first and last named children — resilient against minor
    grammar revisions that might add intermediate annotation nodes.
    """
    named = _named_children(assignment_node)
    if len(named) < 2:
        return None, None
    return named[0], named[-1]


def _lhs_identifier_name(parsed: ParsedSource, lhs_node) -> str:
    """Return the uppercased identifier name from an assignment LHS,
    or an empty string when the LHS is not a single local variable."""
    if lhs_node is None:
        return ""
    if lhs_node.type in {"local_variable", "identifier", "variable"}:
        return parsed.node_text(lhs_node).strip().upper()
    return ""


def _rhs_contains_non_read_taint(parsed: ParsedSource, rhs_node) -> bool:
    if rhs_node is None:
        return False
    text = parsed.node_text(rhs_node)
    return any(p.search(text) for p in _NON_READ_TAINT_PATTERNS)


def collect_read_tainted_variables(parsed: ParsedSource) -> set[str]:
    """READ-only subset of the tainted variable set.

    Retained for backwards compatibility / per-source debugging. Most
    callers want :func:`collect_tainted_variables` which covers the
    full Phase 1+ source surface.
    """
    tainted: set[str] = set()
    for node in walk(parsed.tree.root_node):
        if node.type != "command":
            continue
        if not _READ_KEYWORD_RE.match(parsed.node_text(node)):
            continue
        for name in _extract_target_identifiers(_argument_node(node)):
            if name:
                tainted.add(name.upper())
    return tainted


def _sanitized_variables(
    parsed: ParsedSource, sanitizer_names: list[str],
) -> set[str]:
    """Return uppercased variable names assigned from a sanitizer call.

    A sanitizer is a function whose return value is trusted — applying
    it to a tainted value produces a clean value. Configured via
    ``scanners.m.sanitizers`` in ``argus.yml``::

        scanners:
          m:
            sanitizers:
              - "$$VALIDATE^LIBRARY"
              - "$$ESCAPE^HTML"

    Phase 1 detection is conservative: any assignment whose RHS text
    references one of the named sanitizers marks the LHS as sanitized
    for the whole file. Document-order precision (a sanitization that
    happens *after* the sink doesn't actually clean the sink) lands
    with the inter-procedural rewrite.
    """
    if not sanitizer_names:
        return set()
    escaped = "|".join(re.escape(name) for name in sanitizer_names)
    pattern = re.compile(rf"(?:{escaped})", re.IGNORECASE)
    sanitized: set[str] = set()
    for node in walk(parsed.tree.root_node):
        if node.type != "assignment":
            continue
        lhs, rhs = _assignment_lhs_rhs(node)
        if lhs is None or rhs is None:
            continue
        if not pattern.search(parsed.node_text(rhs)):
            continue
        name = _lhs_identifier_name(parsed, lhs)
        if name:
            sanitized.add(name)
    return sanitized


def collect_tainted_variables(
    parsed: ParsedSource,
    config: dict | None = None,
) -> set[str]:
    """Return the set of uppercased identifier names tainted by any
    Phase 1+ source: READ commands, ``$ZARGV`` references in an
    assignment RHS, or HTTP context globals (``^%CGI`` / ``^%REQUEST``
    / ``^%session``) in an assignment RHS.

    ``config`` may carry a ``taint_sources.patterns`` list (regex
    strings, treated as additional matchers against assignment RHS
    text). Use this to extend the source surface for site-specific
    intrinsics (``$ZIO``, custom HTTP globals, vendor-specific input
    routines) without forking the rules:

        scanners:
          m:
            taint_sources:
              patterns:
                - "\\\\$ZIO\\\\b"
                - "\\\\^MyApp\\\\.input\\\\b"

    Invalid regex patterns are silently skipped — the rest of the
    collection continues. Single document pass overall.
    """
    tainted: set[str] = collect_read_tainted_variables(parsed)
    extra_patterns = _compile_extra_patterns(config)
    all_patterns = _NON_READ_TAINT_PATTERNS + tuple(extra_patterns)
    for node in walk(parsed.tree.root_node):
        if node.type != "assignment":
            continue
        lhs, rhs = _assignment_lhs_rhs(node)
        if lhs is None or rhs is None:
            continue
        rhs_text = parsed.node_text(rhs)
        if not any(p.search(rhs_text) for p in all_patterns):
            continue
        name = _lhs_identifier_name(parsed, lhs)
        if name:
            tainted.add(name)
    # Sanitizers explicitly clean variables. Subtract after collection
    # so the user-configured sanitizer set always wins over the
    # built-in source patterns.
    sanitizer_names = (config or {}).get("sanitizers") or []
    if sanitizer_names:
        tainted -= _sanitized_variables(parsed, sanitizer_names)
    return tainted


def _compile_extra_patterns(config: dict | None) -> list[re.Pattern]:
    """Compile user-supplied regex patterns from
    ``config['taint_sources']['patterns']``. Invalid regexes are
    silently dropped so a typo in argus.yml does not abort the scan.
    """
    if not config:
        return []
    raw = (config.get("taint_sources") or {}).get("patterns") or []
    compiled: list[re.Pattern] = []
    for pattern in raw:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error:
            continue
    return compiled


def is_read_command(parsed: ParsedSource, command_node) -> bool:
    """Lightweight predicate for "is this command a READ?" — used by
    rules that walk the tree once incrementally rather than pre-collect
    via ``collect_tainted_variables``. The read-target identifier
    extraction lives in :func:`read_targets`."""
    return bool(_READ_KEYWORD_RE.match(parsed.node_text(command_node)))


def read_targets(command_node) -> list[str]:
    """Identifier tokens read into by a READ command. Returns uppercased
    names for ease of comparison with the tainted set."""
    return [n.upper() for n in _extract_target_identifiers(_argument_node(command_node))]
