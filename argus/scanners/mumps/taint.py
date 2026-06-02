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


# A RHS that *is* a $ORDER / $QUERY traversal yields the next subscript
# key, not the tainted value stored at the node — so it must not carry
# taint to its LHS (the canonical ``F  S I=$O(@G@(I))`` loop iterator).
_TRAVERSAL_RHS_RE = re.compile(r"\$(?:O|ORDER|Q|QUERY)\s*\(", re.IGNORECASE)


# A RHS that *is* a $TEXT / $T self-reference yields the routine's OWN
# source text (a fixed in-program dispatch table read via $T(LABEL+offset)),
# not external input — even when the line OFFSET is a user-controlled index.
# Tainting the LHS because the offset references a tainted var is a false
# positive: it mislabels the canonical VistA menu driver
# ``S X=$T(MENU+OPT) D @$P(X,";",4)`` as RCE. Treat such LHSs as untainted,
# exactly like $ORDER/$QUERY traversal iterators below.
_TEXT_RHS_RE = re.compile(r"^\s*\$(?:T|TEXT)\s*\(", re.IGNORECASE)


def _references_tainted(rhs_text: str, tainted: set[str]) -> bool:
    """True when the RHS text references any already-tainted variable as a
    MUMPS identifier token.

    Boundary class is ``[A-Za-z0-9%]`` (not ``\\b``) so the concatenation
    operator ``_`` does not block a match: in ``"do "_CMD`` the tainted
    ``CMD`` must be seen right after the ``_``.
    """
    if not tainted:
        return False
    upper = rhs_text.upper()
    for name in tainted:
        if re.search(rf"(?<![A-Za-z0-9%]){re.escape(name)}(?![A-Za-z0-9%])", upper):
            return True
    return False


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
    ``scanners.mumps.sanitizers`` in ``argus.yml``::

        scanners:
          mumps:
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


# A RHS that coerces its value to a number cannot carry shell or code
# metacharacters: ``+X`` is the integer prefix of X regardless of X's
# content (``+"12;rm -rf"`` is 12), and the length / numeric intrinsics
# return integers. Such an assignment sanitizes its LHS for injection
# sinks. Require no concatenation (``_``) after the leading ``+`` so a
# string like ``+X_Y`` is NOT mistaken for a pure numeric value.
_NUMERIC_SANITIZE_RE = re.compile(
    r"^\+[^_]*$|^\$(?:L|LENGTH|NUMBER|ZL|ZLENGTH)\(", re.IGNORECASE
)

# MUMPS pattern-match test ``VAR?<pattern>`` / ``VAR'?<pattern>``. The
# Pattern codes: A=alpha, N=numeric, U=uppercase, L=lowercase,
# P=punctuation, C=control, E=everything. A pattern built only from
# A/N/U/L plus counts and groups is a metacharacter-free charset.
_PATTERN_TEST_RE = re.compile(
    r"(?<![\w$.])([%A-Za-z][A-Za-z0-9]*)\s*'?\?\s*([0-9A-Za-z.,()\"]+)"
)
_SAFE_CHARSET_PAT_RE = re.compile(r"^[0-9.,()]*(?:[ANUL][0-9.,()]*)+$", re.IGNORECASE)


def _charset_guard_lines(parsed: ParsedSource) -> dict[str, list[int]]:
    """Map each variable constrained by a metacharacter-free pattern-match
    guard (``I X?1A.7AN`` / ``I X'?1A.7AN Q``) to the 0-based source line(s)
    of the guard.

    A value that must match a pattern of only the alpha/numeric pattern codes
    (A, N, U, L) plus counts/groups cannot contain shell or MUMPS
    metacharacters, so it is safe at a sink — the canonical VistA
    input-validation idiom. Used for FLOW-SENSITIVE sanitization
    (:func:`filter_charset_guarded`): a guard cleans a value only for sinks
    that follow it in the same straight-line label body. A flow-insensitive
    whole-file sanitize would wrongly clear a variable validated on one entry
    path but reaching a sink on a different, unvalidated entry — a false
    negative that hides a real injection. SOUND and conservative: patterns
    with punctuation (P) / control (C) / everything (E) codes, or a string
    literal, are NOT treated as sanitizing.
    """
    guards: dict[str, list[int]] = {}
    for i, line in enumerate(parsed.source_text.splitlines()):
        semi = line.find(";")
        if semi >= 0:
            line = line[:semi]
        for match in _PATTERN_TEST_RE.finditer(line):
            if _SAFE_CHARSET_PAT_RE.match(match.group(2)):
                guards.setdefault(match.group(1).strip().upper(), []).append(i)
    return guards


def _label_lines(parsed: ParsedSource) -> list[int]:
    """0-based line numbers of column-0 labels — the boundaries between
    straight-line label bodies (a guard does not reach across one)."""
    lines: list[int] = []
    for i, raw in enumerate(parsed.source_bytes.split(b"\n")):
        head = raw[:1]
        if head and (head.isalpha() or head.isdigit() or head == b"%"):
            lines.append(i)
    return lines


def filter_charset_guarded(
    parsed: ParsedSource,
    config: dict | None,
    hits: set[str],
    sink_line: int,
) -> set[str]:
    """Drop from ``hits`` any variable a charset pattern-match guard
    constrains *before* this sink within the same label body (no label
    boundary between the guard line and the sink line).

    Flow-sensitive and sound: a guard on a different entry path does not
    suppress the sink, so a validation gap on the sink's own path still
    fires. Per-file maps are cached on ``config``."""
    if not hits:
        return hits
    if config is not None:
        gmap = config.get("_charset_guard_lines")
        if gmap is None:
            gmap = _charset_guard_lines(parsed)
            config["_charset_guard_lines"] = gmap
        labels = config.get("_label_lines")
        if labels is None:
            labels = _label_lines(parsed)
            config["_label_lines"] = labels
    else:
        gmap = _charset_guard_lines(parsed)
        labels = _label_lines(parsed)
    if not gmap:
        return hits
    remaining: set[str] = set()
    for var in hits:
        guard_lines = gmap.get(var)
        if guard_lines and any(
            g <= sink_line and not any(g < label <= sink_line for label in labels)
            for g in guard_lines
        ):
            continue  # constrained before this sink in the same label body
        remaining.add(var)
    return remaining


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
          mumps:
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

    # Single pass: record every assignment's (lhs_name, rhs_text) and seed
    # taint from any direct source pattern in the RHS.
    assignments: list[tuple[str, str]] = []
    traversal_iters: set[str] = set()
    text_sources: set[str] = set()
    numeric_sanitized: set[str] = set()
    for node in walk(parsed.tree.root_node):
        if node.type != "assignment":
            continue
        lhs, rhs = _assignment_lhs_rhs(node)
        if lhs is None or rhs is None:
            continue
        name = _lhs_identifier_name(parsed, lhs)
        if not name:
            continue
        # Take the full RHS expression from the assignment text (everything
        # after the first ``=``), not just the last named child: a leading
        # unary operator (``+N``) or intrinsic wrapper is otherwise dropped,
        # which would miss numeric-coercion sanitization and split taint.
        assign_text = parsed.node_text(node)
        eq = assign_text.find("=")
        rhs_text = assign_text[eq + 1:] if eq >= 0 else parsed.node_text(rhs)
        assignments.append((name, rhs_text))
        stripped = rhs_text.lstrip()
        if _TRAVERSAL_RHS_RE.match(stripped):
            traversal_iters.add(name)
        if _TEXT_RHS_RE.match(stripped):
            text_sources.add(name)
        if _NUMERIC_SANITIZE_RE.match(stripped):
            numeric_sanitized.add(name)
        if any(p.search(rhs_text) for p in all_patterns):
            tainted.add(name)

    # Sanitizers clean a value; subtract them up front so they neither
    # count as tainted nor propagate taint downstream. Built-in sanitizers
    # (numeric coercion, charset-constraining pattern-match guards) join the
    # config-supplied ones — all SOUND, i.e. they only ever remove taint.
    sanitizer_names = (config or {}).get("sanitizers") or []
    sanitized = _sanitized_variables(parsed, sanitizer_names) if sanitizer_names else set()
    # Numeric coercion is a SOUND flow-insensitive sanitizer: ``S N=+X``
    # creates a new value that is a number regardless of path. Charset
    # pattern-match guards are flow-SENSITIVE (they constrain the same
    # variable only on the path past the guard) and are applied per-sink via
    # filter_charset_guarded, not subtracted globally here.
    sanitized |= numeric_sanitized
    tainted -= sanitized
    # A variable that is ever a $ORDER/$QUERY loop iterator holds subscript
    # keys from a structure walk, not an external value. Flow-insensitive
    # taint can't see that a later ``S X=$Q(@X)`` overwrites an earlier
    # tainted X, so exclude such names entirely (a Phase-1 stand-in for
    # flow-sensitive taint) — this is the dominant @-indirection FP source.
    tainted -= traversal_iters
    # $TEXT/$T self-source assignments hold fixed program text, not external
    # input; exclude them (and block re-tainting via propagation below) so
    # the VistA menu-driver dispatch ``S X=$T(MENU+OPT) D @$P(X,";",4)`` is
    # not flagged as injection. Same flow-insensitive Phase-1 stand-in.
    tainted -= text_sources

    # Transitive propagation to a fixpoint. Real MUMPS injection is built
    # up across several SET / concatenation steps (``S CMD="do "_ARG``), so
    # an assignment whose RHS references an already-tainted variable taints
    # its LHS too. Without this the source->sink chain breaks and the
    # taint-sink rules (M001/M003/M005/M006) never fire on real code.
    # $ORDER/$QUERY traversal results are excluded (the LHS gets a subscript
    # key, not the tainted value), and sanitized LHSs stay clean.
    changed = True
    while changed:
        changed = False
        for name, rhs_text in assignments:
            if (
                name in tainted
                or name in sanitized
                or name in traversal_iters
                or name in text_sources
            ):
                continue
            if _TRAVERSAL_RHS_RE.match(rhs_text.lstrip()):
                continue
            if _references_tainted(rhs_text, tainted):
                tainted.add(name)
                changed = True
    return tainted


def resolve_tainted(parsed: ParsedSource, config: dict | None) -> set[str]:
    """Return the per-file tainted-variable set, reusing a shared copy
    when the scanner has already computed it.

    ``MumpsScanner.scan`` computes the taint set once per file and stashes
    it on ``config['_tainted']`` so the four taint-sink rules
    (M001/M003/M005/M006) don't each re-walk the tree to recompute the
    identical set. When ``_tainted`` is absent — standalone rule use, or
    a test that builds its own config — fall back to computing it.
    """
    if config is not None:
        shared = config.get("_tainted")
        if shared is not None:
            return shared
    return collect_tainted_variables(parsed, config)


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
