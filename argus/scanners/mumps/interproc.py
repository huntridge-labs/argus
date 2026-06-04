"""Inter-procedural taint propagation across the MUMPS call graph.

Phase 1 taint detection is intra-file: a value tainted in routine A
never taints routine B. This module adds the first real cross-routine
hop — when A calls ``ENTRY^B(actual, ...)`` and ``actual`` references a
variable tainted in A, B's corresponding formal parameter becomes
tainted, so B's sinks (XECUTE / OPEN-USE / dispatch / external call of
that formal) fire.

Design notes:

* **Strictly opt-in.** Driven by ``scanners.mumps.interprocedural.enabled``
  (default False). When off, the scanner never calls this and behavior
  is byte-identical to the intra-file analysis.
* **Monotone worklist to fixpoint.** Inbound taint sets only grow, so
  iteration terminates and is naturally cycle-safe (recursion /
  mutual recursion can't loop forever). ``max_depth`` (default 1) caps
  how many call hops a taint value may travel; depth 1 = a caller's
  *local* taint reaches its direct callees' formals.
* **Sanitizer-aware integration happens at the sink.** This module only
  computes which formals are inbound-tainted; the scanner unions them
  into the callee's taint set, which has already had sanitized variables
  removed.

Deferred (documented limitations): return-value taint (callee returns a
tainted value the caller stores), global-through-routine flow, extrinsic
``$$fn^rtn`` argument propagation, and per-finding provenance metadata.
"""

from __future__ import annotations

from .callgraph import CallGraph


def propagate_inbound_taint(
    callgraph: CallGraph,
    local_taint: dict[str, set[str]],
    max_depth: int = 1,
) -> dict[str, set[str]]:
    """Return a map of routine name -> set of formal names tainted via a
    caller.

    ``local_taint`` maps each routine name to the set of variable names
    tainted *within* that routine (from READ / $ZARGV / HTTP globals).
    The result is the inbound-formal taint each routine receives from
    its callers, ready to be unioned into that routine's taint set
    before its sinks are checked.
    """
    inbound: dict[str, set[str]] = {}
    if max_depth < 1:
        return inbound

    for _hop in range(max_depth):
        changed = False
        for edge in callgraph.edges:
            caller_tainted = set(local_taint.get(edge.caller, ()))
            caller_tainted |= inbound.get(edge.caller, set())
            if not caller_tainted:
                continue
            callee = callgraph.routines.get(edge.callee_routine)
            if callee is None:
                continue
            # Resolve the entry label: an explicit ``LABEL^RTN`` uses
            # LABEL; a bare ``^RTN`` enters at the routine's principal
            # label (conventionally the routine name).
            entry = edge.callee_label or edge.callee_routine
            formals = callee.entry_formals.get(entry)
            if not formals:
                continue
            for i, actual_names in enumerate(edge.actual_arg_names):
                if i >= len(formals):
                    break
                if not (actual_names & caller_tainted):
                    continue
                formal = formals[i]
                if not formal:
                    continue
                bucket = inbound.setdefault(edge.callee_routine, set())
                if formal not in bucket:
                    bucket.add(formal)
                    changed = True
        if not changed:
            break
    return inbound
