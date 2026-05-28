"""M205 — label body falls through into the next label (diagnostic).

A MUMPS routine's labels are entry points, not closed blocks. If the
body of ``LABELA`` does not end with an unconditional ``Q`` / ``H`` /
``G`` (or another label-changing operation), execution falls through
into ``LABELB`` when ``D LABELA`` runs. That's almost always a bug:
``D LABELA`` callers expected the routine to end at LABELA, not to
continue into LABELB.

Detection:

1. Walk the file's top-level children in document order.
2. For each adjacent pair of ``routine_definition`` siblings, inspect
   the first one's ``block`` subtree (or direct children when the
   grammar parsed it without a block wrapper).
3. Find the last ``command`` / ``do_statement`` / ``assignment`` in
   that body.
4. If the last command is not an unconditional terminator (``Q``,
   ``H``, ``G``, or a ``GOTO`` to an explicit label), flag M205 on
   the second routine_definition's label — the one being reached by
   fallthrough.

Conditional terminators (``Q:cond``) are recognized via the same
``Q:`` postconditional pattern M102 uses, and they do *not* prevent
the fallthrough flag — execution still reaches the next label when
``cond`` is false.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule

# Anchored to the command's leading token. Excludes postconditionals
# by requiring whitespace or end-of-string after the keyword.
_UNCONDITIONAL_TERMINATOR_RE = re.compile(
    r"^\s*(?:Q(?:UIT)?|H(?:ALT)?|G(?:OTO)?)(?:\s|$)",
    re.IGNORECASE,
)


def _body_for(routine_def_node):
    """Return the block / command sequence under a ``routine_definition``.

    The grammar usually wraps the body in a ``block`` node, but when
    the first label has only one or two commands it sometimes flattens
    into direct children of the ``routine_definition``. Return the
    block subtree when present, otherwise the routine_definition itself
    so the caller can iterate its child commands.
    """
    for child in routine_def_node.children:
        if child.type == "block":
            return child
    return routine_def_node


def _last_executable_child(body_node):
    """Return the last executable statement child of ``body_node``,
    or None when the body has none.

    Executable statements: ``command``, ``do_statement``, ``assignment``
    in this grammar. Comments and the label declaration itself don't
    count toward control-flow termination.
    """
    executable: Optional[object] = None
    for child in body_node.children:
        if child.type in {"command", "do_statement", "assignment"}:
            executable = child
    return executable


def _label_name(parsed: ParsedSource, label_node) -> str:
    text = parsed.node_text(label_node).strip()
    return text.split(None, 1)[0] if text else ""


class LabelFallthroughRule(Rule):
    id = "M205"
    severity = Severity.INFO
    title = "Label body falls through into the following label"
    cwe = None  # diagnostic

    def analyze(self, parsed: ParsedSource) -> Iterable[Finding]:
        root = parsed.tree.root_node
        # Collect top-level routine_definition nodes in document order.
        # ``program`` is typically the root with routine_definitions as
        # children; some files put them under a different parent so we
        # walk shallowly.
        rdefs = []
        for child in root.children:
            if child.type == "routine_definition":
                rdefs.append(child)
            # Some grammars wrap everything in ``program`` — descend one.
            elif child.type == "program":
                for grandchild in child.children:
                    if grandchild.type == "routine_definition":
                        rdefs.append(grandchild)
        if len(rdefs) < 2:
            return
        for i in range(len(rdefs) - 1):
            current = rdefs[i]
            following = rdefs[i + 1]
            body = _body_for(current)
            last = _last_executable_child(body)
            if last is None:
                # Empty body. Fallthrough still happens, but flagging
                # an empty label is noisier than useful — skip.
                continue
            text = parsed.node_text(last)
            if _UNCONDITIONAL_TERMINATOR_RE.match(text):
                continue
            # No terminator — execution falls through. Find the
            # following label to anchor the finding there.
            following_label = None
            for child in following.children:
                if child.type == "label":
                    following_label = child
                    break
            if following_label is None:
                continue
            current_label = None
            for child in current.children:
                if child.type == "label":
                    current_label = child
                    break
            current_name = _label_name(parsed, current_label) if current_label else "<unknown>"
            following_name = _label_name(parsed, following_label)
            yield self.make_finding(
                parsed,
                following_label,
                description=(
                    f"Label '{current_name}' ends without an unconditional "
                    f"Q / H / G, so execution falls through into '{following_name}'. "
                    "Callers of 'D " + current_name + "' will continue past the "
                    "label boundary. Add an explicit QUIT at the end of "
                    f"'{current_name}', or merge the labels if the fallthrough "
                    "is intentional."
                ),
                metadata={
                    "preceding_label": current_name,
                    "fallthrough_into": following_name,
                },
            )
