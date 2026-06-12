"""OSCAL 1.1.2 Assessment Results reporter.

Emits a single ``argus-results.oscal.json`` per scan — a NIST OSCAL
Assessment Results document mapping every scanner finding to one or more
NIST SP 800-53 Rev 5 controls via
[argus.core.control_mapping](argus/core/control_mapping.py). The output is
designed for ingestion by GRC platforms (eMASS, Xacta, RegScale, etc.) as
continuous-monitoring evidence supporting an Authority to Operate.

Design choices worth knowing as a reader (full rationale in ADR-023 in
``.ai/decisions.yaml``):

* **Validated against the official NIST schema.** The schema file ships
  inside the package at ``argus/compliance/schemas/`` and is exercised in
  the test suite. Argus does not depend on ``jsonschema`` at runtime — the
  reporter emits well-formed OSCAL and CI verifies it; user environments
  pay no validation cost.

* **Deterministic UUIDs.** All ``uuid`` fields are UUIDv5 derived from
  scan content. The same scan output yields the same OSCAL document; GRC
  tools keyed on ``uuid`` for "have I already imported this finding?" get
  stable identity for free.

* **One OSCAL finding per (Argus finding × control).** An Argus finding
  that maps to multiple controls (a hardcoded secret hits IA-5 *and*
  SC-28) becomes multiple OSCAL findings — one per control — because
  OSCAL's ``finding`` assembly carries a single ``target``. Auditors get
  one row per control implication, which is what GRC scoring needs.

* **Unmapped findings are emitted, not dropped.** A finding whose scanner
  + CWE both miss the mapping tables still appears, pointed at a synthetic
  ``argus-unmapped`` target with the original context preserved in
  ``props``. The compliance reviewer sees the gap.

* **No external Assessment Plan.** ``import-ap.href`` self-references the
  AR's own uuid by default; override via ``ARGUS_OSCAL_IMPORT_AP_HREF``
  when emitting evidence that lives alongside a published AP file.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid as _uuid_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.core.control_mapping import ControlRef, map_finding
from argus.core.models import Finding, ScanResult, ScanSummary, Severity

_DEFAULT_OUTPUT_DIR = Path("./argus-results")
_OUTPUT_FILENAME = "argus-results.oscal.json"
_OSCAL_VERSION = "1.1.2"
_ARGUS_NAMESPACE = "https://huntridge-labs.github.io/argus/oscal"

# Deterministic UUIDv5 namespace seed. Anchored to a fixed UUIDv4 so all
# UUIDv5 values produced by this reporter share a single root; rotating
# this value would orphan every previously-emitted document's identity,
# so it must never change.
_ARGUS_UUID_NAMESPACE = _uuid_mod.UUID("8b2c7c1e-7b1f-4c3e-9d2a-1f5a7e2b6c34")

# OSCAL Token requires NCName-like ids. This sentinel covers unmapped
# findings so they don't break schema validation when the mapping tables
# don't yet cover a given scanner+rule.
_UNMAPPED_CONTROL_ID = "argus-unmapped"

# Severities that don't represent a control failure — INFO and UNKNOWN
# round-trip as ``satisfied`` so a GRC tool isn't double-counting linter
# noise as a control gap.
_SATISFIED_SEVERITIES = {Severity.INFO, Severity.UNKNOWN}


class OscalReporter:
    """Emit an OSCAL 1.1.2 Assessment Results document."""

    def report(self, summary: ScanSummary, output_dir: Optional[Path] = None) -> Path:
        """Write ``output_dir/argus-results.oscal.json`` and return its path."""
        dest = Path(output_dir) if output_dir else _DEFAULT_OUTPUT_DIR
        dest.mkdir(parents=True, exist_ok=True)
        filepath = dest / _OUTPUT_FILENAME
        filepath.write_text(
            json.dumps(self._build(summary), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return filepath

    def _build(self, summary: ScanSummary) -> dict:
        # Last-modified is the only deliberately non-deterministic field —
        # the assessment really did finish "now," and OSCAL ingestion tools
        # use it to order successive scans. Everything else is content-
        # derived so re-runs produce a byte-identical ``results`` array.
        now_iso = _now_iso()
        ar_uuid = _uuid5_for(b"assessment-results:" + _summary_digest(summary).encode())
        return {
            "assessment-results": {
                "uuid": str(ar_uuid),
                "metadata": _build_metadata(summary, now_iso),
                "import-ap": {"href": _import_ap_href(ar_uuid)},
                "results": [_build_result(r, now_iso) for r in summary.results],
            }
        }


def _build_result(result: ScanResult, start_iso: str) -> dict:
    """One OSCAL ``result`` per scanner — mirrors SARIF's one-run-per-scanner.

    ``findings`` is optional in OSCAL but when present must be non-empty
    (``minItems: 1``). A scanner that ran cleanly with zero findings is a
    valid OSCAL outcome — emit the result without the ``findings`` key
    rather than an empty array that breaks schema validation.
    """
    findings: list[dict] = []
    for f in result.findings:
        findings.extend(_expand_finding(f, result.scanner))
    out = {
        "uuid": str(_uuid5_for(f"result:{result.scanner}".encode())),
        "title": f"Argus {result.scanner} scan",
        "description": (
            f"Findings from the Argus {result.scanner} scanner. "
            "Each finding targets one or more NIST SP 800-53 Rev 5 controls "
            "via the in-repo argus/compliance/mappings/ tables."
        ),
        "start": start_iso,
        "reviewed-controls": {
            "control-selections": [{"include-all": {}}],
        },
    }
    if findings:
        out["findings"] = findings
    return out


def _expand_finding(finding: Finding, scanner: str) -> list[dict]:
    """Return one OSCAL ``finding`` per implicated control.

    A finding mapped to N controls becomes N OSCAL findings — shared
    title/description/props, differing target. Unmapped findings still
    produce exactly one OSCAL finding, pointed at ``argus-unmapped``.
    """
    refs = map_finding(finding)
    if not refs:
        return [_finding_dict(finding, scanner, control_ref=None)]
    return [_finding_dict(finding, scanner, control_ref=ref) for ref in refs]


def _finding_dict(finding: Finding, scanner: str, control_ref: Optional[ControlRef]) -> dict:
    target_id, status_state, status_reason, props = _target_payload(finding, control_ref)
    fuuid = _uuid5_for(
        b"finding:" + "|".join(
            [scanner, finding.id or "", finding.location or "", target_id],
        ).encode()
    )
    description = finding.description or finding.title or finding.id or "(no description)"
    return {
        "uuid": str(fuuid),
        "title": finding.title or finding.id or "(untitled finding)",
        "description": description,
        "target": {
            "type": "objective-id",
            "target-id": target_id,
            "status": {
                "state": status_state,
                "reason": status_reason,
            },
        },
        "props": props,
    }


def _target_payload(
    finding: Finding,
    control_ref: Optional[ControlRef],
) -> tuple[str, str, str, list[dict]]:
    """Derive target id, status, and props from a finding + its mapping.

    All four outputs are tied to the same inputs: unmapped findings need
    the synthetic id AND the unmapped prop AND a not-satisfied status, all
    consistently. Computed together so they can't drift.
    """
    severity = finding.severity.value if finding.severity else "unknown"
    props: list[dict] = [
        {"name": "argus-scanner", "ns": _ARGUS_NAMESPACE, "value": finding.scanner or ""},
        {"name": "argus-rule-id", "ns": _ARGUS_NAMESPACE, "value": finding.id or ""},
        {"name": "argus-severity", "ns": _ARGUS_NAMESPACE, "value": severity},
    ]
    if finding.location:
        props.append({"name": "argus-location", "ns": _ARGUS_NAMESPACE, "value": finding.location})
    if finding.cwe:
        props.append({"name": "argus-cwe", "ns": _ARGUS_NAMESPACE, "value": finding.cwe})
    if finding.cve:
        props.append({"name": "argus-cve", "ns": _ARGUS_NAMESPACE, "value": finding.cve})

    if control_ref is None:
        # Can't attest to any control — emitting ``satisfied`` would be a
        # false positive on coverage. ``other`` reason flags the entry as
        # not-failure-not-pass for GRC tools that bucket on reason.
        props.append({"name": "argus-unmapped", "ns": _ARGUS_NAMESPACE, "value": "true"})
        return (_UNMAPPED_CONTROL_ID, "not-satisfied", "other", props)

    is_satisfied = finding.severity in _SATISFIED_SEVERITIES
    state = "satisfied" if is_satisfied else "not-satisfied"
    reason = "pass" if is_satisfied else "fail"
    props.append({"name": "argus-control-source", "ns": _ARGUS_NAMESPACE, "value": control_ref.source})
    return (control_ref.control_id, state, reason, props)


def _build_metadata(summary: ScanSummary, now_iso: str) -> dict:
    version = _argus_version()
    return {
        "title": "Argus Security Scan — Assessment Results",
        "last-modified": now_iso,
        "version": version,
        "oscal-version": _OSCAL_VERSION,
        "props": [
            {"name": "argus-version", "ns": _ARGUS_NAMESPACE, "value": version},
            {
                "name": "argus-finding-count",
                "ns": _ARGUS_NAMESPACE,
                "value": str(summary.total_count),
            },
        ],
    }


def _now_iso() -> str:
    """Current UTC time as an OSCAL DateTimeWithTimezoneDatatype string.

    The schema regex requires a timezone designator (Z or ±HH:MM); a bare
    ``datetime.now().isoformat()`` would be rejected.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _uuid5_for(payload: bytes) -> _uuid_mod.UUID:
    digest = hashlib.sha256(payload).hexdigest()
    return _uuid_mod.uuid5(_ARGUS_UUID_NAMESPACE, digest)


def _summary_digest(summary: ScanSummary) -> str:
    """Stable digest used to derive the AR uuid.

    Hashes scanner names + finding ids + locations + severities — the
    fields that genuinely identify "which findings did this scan produce."
    Cosmetic changes (title rewording in a scanner version bump) don't
    perturb the AR uuid, so GRC tools keyed on uuid see a stable identity.
    """
    h = hashlib.sha256()
    for result in summary.results:
        h.update(result.scanner.encode())
        h.update(b"\0")
        for finding in result.findings:
            h.update((finding.id or "").encode())
            h.update(b"|")
            h.update((finding.location or "").encode())
            h.update(b"|")
            h.update(finding.severity.value.encode())
            h.update(b"\n")
    return h.hexdigest()[:16]


def _argus_version() -> str:
    """Return the running argus version, "0.0.0" if introspection fails.

    The version appears only in OSCAL metadata; a fallback sentinel can't
    break document validity. Keeps the reporter functional in odd install
    shapes (PYTHONPATH-only, in-tree dev runs before ``__version__`` is
    generated).
    """
    try:
        from argus import __version__
        return str(__version__)
    except Exception:  # noqa: BLE001  # pragma: no cover — defensive fallback
        return "0.0.0"


def _import_ap_href(ar_uuid: _uuid_mod.UUID) -> str:
    """``import-ap.href`` — self-reference unless the env override is set.

    OSCAL requires an Assessment Plan reference. A fragment identifier
    pointing at the AR's own uuid keeps the field schema-valid for the
    common "no published AP" case; ``ARGUS_OSCAL_IMPORT_AP_HREF`` lets
    deployments that *do* have an AP point at it.
    """
    override = os.environ.get("ARGUS_OSCAL_IMPORT_AP_HREF")
    return override if override else f"#{ar_uuid}"
