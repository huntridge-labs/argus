"""Triage decisions → OpenVEX + scanner ignore files (Phase 7).

The terminal viewer lets a user bulk-triage findings — mark them false
positive, not-exploitable, risk-accepted, or under-investigation, with a
reason. This module turns those decisions into durable, auditable artifacts:

- an **OpenVEX** document (the audit trail: per-CVE status + justification +
  reason + author + timestamp), the answer to the "where do triage decisions
  come from?" question the OpenVEX *reporter* (``argus/reporters/openvex.py``)
  deliberately left open, and
- **scanner ignore-file entries** (``.trivyignore`` / ``.gitleaksignore``) so
  the next scan respects the decision.

UI-free on purpose (same rule as the rest of the core): the VEX builders,
the merge, and the ignore-entry formatters are pure and unit-tested; only
the file writes touch disk (tested with ``tmp_path``). The Textual screen is
a thin caller.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# Mirrors argus/reporters/openvex.py; defined here so core doesn't depend on
# the reporters layer. Keep in sync if the OpenVEX version bumps.
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

# OpenVEX statuses (the four the spec defines).
STATUS_NOT_AFFECTED = "not_affected"
STATUS_AFFECTED = "affected"
STATUS_FIXED = "fixed"
STATUS_UNDER_INVESTIGATION = "under_investigation"

# OpenVEX justification vocabulary — required for a ``not_affected`` statement
# that has no free-text impact_statement.
JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)

# Triage action → (VEX status, default justification). The actions the
# viewer offers; the user supplies the free-text reason.
ACTIONS: dict[str, tuple[str, str]] = {
    "false_positive": (STATUS_NOT_AFFECTED, "vulnerable_code_not_present"),
    "not_exploitable": (STATUS_NOT_AFFECTED, "vulnerable_code_not_in_execute_path"),
    "accept_risk": (STATUS_AFFECTED, ""),
    "investigating": (STATUS_UNDER_INVESTIGATION, ""),
}

# Human labels for the action picker.
ACTION_LABELS: dict[str, str] = {
    "false_positive": "False positive",
    "not_exploitable": "Not exploitable",
    "accept_risk": "Accept risk",
    "investigating": "Under investigation",
}


@dataclass(frozen=True)
class TriageDecision:
    """One triage decision, ready to serialize to VEX / ignore files."""

    cve: str
    product: str = ""        # PURL or product id (may be empty for non-SCA)
    status: str = STATUS_NOT_AFFECTED
    justification: str = ""  # VEX justification (for not_affected)
    reason: str = ""         # free-text audit note
    scanner: str = ""
    author: str = "argus-console"
    timestamp: str = ""      # ISO 8601; filled by the builder when empty


def decision_for(
    action: str,
    *,
    cve: str,
    product: str = "",
    reason: str = "",
    scanner: str = "",
    author: str = "argus-console",
    timestamp: str = "",
) -> TriageDecision:
    """Build a :class:`TriageDecision` from a triage *action* keyword.

    ``action`` is a key of :data:`ACTIONS`; unknown actions fall back to
    ``under_investigation`` (the safe "no decision yet" status).
    """
    status, justification = ACTIONS.get(action, (STATUS_UNDER_INVESTIGATION, ""))
    return TriageDecision(
        cve=cve, product=product, status=status, justification=justification,
        reason=reason, scanner=scanner, author=author, timestamp=timestamp,
    )


def to_vex_statement(decision: TriageDecision) -> dict:
    """Render one decision as an OpenVEX statement dict."""
    statement: dict = {
        "vulnerability": {"name": decision.cve},
        "status": decision.status,
    }
    if decision.product:
        statement["products"] = [{"@id": decision.product}]
    if decision.status == STATUS_NOT_AFFECTED:
        # not_affected needs a justification OR an impact_statement.
        if decision.justification:
            statement["justification"] = decision.justification
        if decision.reason:
            statement["impact_statement"] = decision.reason
    elif decision.status == STATUS_AFFECTED and decision.reason:
        # "risk accepted" — record the action taken / rationale.
        statement["action_statement"] = decision.reason
    elif decision.reason:
        statement["impact_statement"] = decision.reason
    if decision.timestamp:
        statement["timestamp"] = decision.timestamp
    return statement


def build_vex_document(
    decisions: Iterable[TriageDecision],
    *,
    author: str = "argus-console",
    timestamp: str | None = None,
) -> dict:
    """Build a complete OpenVEX v0.2.0 document from triage decisions.

    The ``@id`` is a content digest so re-emitting the same decisions yields
    the same id (idempotent, diffable); the document timestamp is the only
    non-deterministic field and can be pinned via ``timestamp``.
    """
    stamp = timestamp or datetime.now(timezone.utc).isoformat()
    # VEX is keyed by vulnerability name — only CVE-bearing decisions belong
    # here. Secret/CVE-less findings are recorded via the ignore files instead.
    statements = [
        to_vex_statement(_with_timestamp(d, stamp)) for d in decisions if d.cve
    ]
    digest = hashlib.sha256(
        json.dumps(statements, sort_keys=True).encode("utf-8"),
    ).hexdigest()[:16]
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"https://huntridge-labs.github.io/argus/vex/{digest}",
        "author": author,
        "role": "Document Creator",
        "timestamp": stamp,
        "version": 1,
        "statements": statements,
    }


def merge_vex_documents(existing: dict, new: dict) -> dict:
    """Merge ``new`` statements into ``existing``, newest decision winning.

    Statements are keyed by (vulnerability name, product id). A re-triage of
    the same finding replaces the prior statement rather than duplicating it.
    Bumps the document ``version`` and refreshes metadata from ``new``.
    """
    merged: dict[tuple[str, str], dict] = {}
    for statement in _statements(existing) + _statements(new):
        merged[_statement_key(statement)] = statement
    ordered = [merged[k] for k in sorted(merged)]
    prior_version = existing.get("version", 1) if isinstance(existing, dict) else 1
    return {
        "@context": new.get("@context", OPENVEX_CONTEXT),
        "@id": new.get("@id", existing.get("@id", "")),
        "author": new.get("author", "argus-console"),
        "role": "Document Creator",
        "timestamp": new.get("timestamp", ""),
        "version": (prior_version if isinstance(prior_version, int) else 1) + 1,
        "statements": ordered,
    }


def trivyignore_entries(decisions: Iterable[TriageDecision]) -> list[str]:
    """``.trivyignore`` lines for the suppressing decisions.

    Trivy ignores a vuln by its id; we precede each with a ``# reason``
    comment so the file stays an audit trail too. Only decisions that
    actually suppress (not ``under_investigation``) and carry a CVE qualify.
    """
    lines: list[str] = []
    for d in decisions:
        if d.status == STATUS_UNDER_INVESTIGATION or not d.cve:
            continue
        note = d.reason or ACTION_LABELS.get(d.status, d.status)
        lines.append(f"# {note}")
        lines.append(d.cve)
    return lines


def gitleaksignore_entries(decisions: Iterable[TriageDecision]) -> list[str]:
    """``.gitleaksignore`` fingerprints for secret-finding decisions.

    Gitleaks keys ignores by a per-finding fingerprint; we emit one when the
    decision carries it (in ``product``, where the caller stashes the
    fingerprint for secret scanners). Skips decisions without one.
    """
    lines: list[str] = []
    for d in decisions:
        if d.status == STATUS_UNDER_INVESTIGATION or not d.product:
            continue
        if d.scanner and "gitleaks" not in d.scanner.lower():
            continue
        if d.reason:
            lines.append(f"# {d.reason}")
        lines.append(d.product)
    return lines


def write_suppressions(
    repo_root: Path,
    decisions: list[TriageDecision],
    *,
    timestamp: str | None = None,
    author: str = "argus-console",
) -> dict[str, Path]:
    """Write the VEX doc + ignore-file entries; return ``{artifact: path}``.

    Appends to existing ignore files (never clobbers) and merges into an
    existing ``argus-results.openvex.json`` if present. Best-effort per
    artifact: a write that fails is omitted from the returned map rather than
    aborting the others.
    """
    written: dict[str, Path] = {}
    written.update(_write_vex(repo_root, decisions, timestamp=timestamp, author=author))
    written.update(_append_ignore(
        repo_root / ".trivyignore", trivyignore_entries(decisions), key="trivyignore",
    ))
    written.update(_append_ignore(
        repo_root / ".gitleaksignore", gitleaksignore_entries(decisions),
        key="gitleaksignore",
    ))
    return written


# -- internals --------------------------------------------------------------

def _with_timestamp(decision: TriageDecision, stamp: str) -> TriageDecision:
    if decision.timestamp:
        return decision
    return TriageDecision(
        cve=decision.cve, product=decision.product, status=decision.status,
        justification=decision.justification, reason=decision.reason,
        scanner=decision.scanner, author=decision.author, timestamp=stamp,
    )


def _statements(doc: object) -> list[dict]:
    if isinstance(doc, dict):
        return [s for s in doc.get("statements", []) if isinstance(s, dict)]
    return []


def _statement_key(statement: dict) -> tuple[str, str]:
    name = str((statement.get("vulnerability") or {}).get("name", ""))
    products = statement.get("products") or [{}]
    product = str(products[0].get("@id", "")) if products else ""
    return (name, product)


def _write_vex(
    repo_root: Path,
    decisions: list[TriageDecision],
    *,
    timestamp: str | None,
    author: str,
) -> dict[str, Path]:
    path = repo_root / "argus-results.openvex.json"
    new_doc = build_vex_document(decisions, author=author, timestamp=timestamp)
    try:
        if path.is_file():
            existing = json.loads(path.read_text(encoding="utf-8"))
            new_doc = merge_vex_documents(existing, new_doc)
        path.write_text(json.dumps(new_doc, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError):
        return {}
    return {"openvex": path}


def _append_ignore(path: Path, entries: list[str], *, key: str) -> dict[str, Path]:
    if not entries:
        return {}
    try:
        existing = path.read_text(encoding="utf-8") if path.is_file() else ""
        block = "\n".join(entries)
        prefix = "" if (not existing or existing.endswith("\n")) else "\n"
        path.write_text(f"{existing}{prefix}{block}\n", encoding="utf-8")
    except OSError:
        return {}
    return {key: path}
