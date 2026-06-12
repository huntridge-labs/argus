"""Map scanner findings to NIST SP 800-53 Rev 5 controls.

The OSCAL reporter ([argus/reporters/oscal.py](argus/reporters/oscal.py))
needs every finding it emits to point at one or more 800-53 control IDs so
GRC tools (eMASS, Xacta, etc.) can ingest the Assessment Results as
continuous-monitoring evidence. This module is the pure, in-memory side of
that pipeline: feed it a ``Finding``, get back a list of ``ControlRef``
objects naming the controls the finding implicates.

The mapping data lives in YAML under ``argus/compliance/mappings/``. The
files are deliberately data, not code — compliance reviewers can audit and
extend them without touching Python. See ADR-023 (OSCAL design choices) in
``.ai/decisions.yaml`` for the rationale.

Resolution order (most-specific wins, fall through to the next on miss):

1. ``finding.metadata["nist_controls"]`` — scanner-supplied override. Lets a
   scanner that already knows its own control mapping (future hook) skip the
   lookup tables entirely.
2. ``mappings/<scanner>.yaml[finding.id]`` — rule-level mapping keyed by the
   scanner's native rule ID (Bandit ``B105``, Gitleaks rule name, OSV CVE,
   …).
3. ``mappings/<scanner>.yaml[".default"]`` — scanner-level fallback. Picks
   up findings whose specific rule isn't mapped yet but whose scanner has a
   sensible whole-category default (e.g. all Gitleaks rules implicate
   IA-5).
4. ``mappings/cwe-to-nist.yaml[finding.cwe]`` — CWE-driven fallback. Only
   fires when the scanner populated ``finding.cwe``; many do (Bandit,
   Opengrep), several don't (Trivy-IaC, Checkov) — those need to rely on
   per-scanner mappings instead.
5. No match → return an empty list. The reporter still emits the finding,
   tagged with ``argus-unmapped`` so an auditor sees it rather than losing
   it to silent filtering.

Loading is cached for the life of the process. Tests force a rebuild via
``_reset_cache_for_tests()``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml

from argus.core.models import Finding

logger = logging.getLogger("argus")

# Mapping data ships inside the package so a clean ``pip install
# argus-security`` carries it without needing a follow-up download step.
_MAPPING_ROOT = Path(__file__).resolve().parent.parent / "compliance" / "mappings"

# The CWE fallback file is special-cased — every scanner that populates
# ``finding.cwe`` falls through to it, so it isn't keyed by scanner name.
_CWE_FALLBACK_FILENAME = "cwe-to-nist.yaml"

# Sentinel key used inside a per-scanner mapping file to declare a
# scanner-wide default (step 3 in the resolution order). Chosen so it can't
# collide with a real rule ID — no scanner uses a leading dot.
_SCANNER_DEFAULT_KEY = ".default"


@dataclass(frozen=True)
class ControlRef:
    """One NIST 800-53 control implicated by a finding.

    ``control_id`` is the canonical lowercase form ("ac-3", "si-10") — this
    matches the OSCAL Token datatype constraint and the convention used in
    NIST's own OSCAL catalogs. Casing is normalized at load time so mapping
    YAML files can stay readable ("AC-3").

    ``source`` records which precedence tier produced this mapping
    ("metadata", "rule", "scanner-default", "cwe"). Carried through so the
    reporter can stamp it into OSCAL ``props`` for auditor traceability and
    so tests can assert which tier was hit without inspecting internals.
    """

    control_id: str
    source: str


def map_finding(finding: Finding) -> list[ControlRef]:
    """Return the 800-53 controls implicated by ``finding``.

    Pure function — no I/O after the cached load. Order of returned controls
    is deterministic: the order they appear in the matching YAML list, with
    duplicates removed (preserving first occurrence). An empty list means
    "no mapping" and is a normal, expected outcome the reporter handles
    explicitly (it tags the finding as unmapped rather than dropping it).
    """
    seen: set[str] = set()
    refs: list[ControlRef] = []

    def _add(controls: list[str], source: str) -> None:
        for raw in controls:
            cid = _normalize_control_id(raw)
            if cid and cid not in seen:
                seen.add(cid)
                refs.append(ControlRef(control_id=cid, source=source))

    # Each tier short-circuits the next on match. This matters because the
    # tiers are NOT additive: a scanner that supplies metadata.nist_controls
    # is asserting it knows the full control set for this finding, so
    # falling through to the rule-level map would add controls the scanner
    # already declined to include. Same for rule-vs-default and
    # rule-vs-CWE: each lower tier is a backstop, not a supplement.

    # Tier 1: scanner-supplied override via Finding.metadata
    meta_controls = _coerce_control_list(finding.metadata.get("nist_controls"))
    if meta_controls:
        _add(meta_controls, "metadata")
        return refs

    scanner_mapping = _load_scanner_mapping(finding.scanner)

    # Tier 2: rule-level
    rule_controls = _coerce_control_list(scanner_mapping.get(finding.id))
    if rule_controls:
        _add(rule_controls, "rule")
        return refs

    # Tier 3: scanner-level default
    default_controls = _coerce_control_list(scanner_mapping.get(_SCANNER_DEFAULT_KEY))
    if default_controls:
        _add(default_controls, "scanner-default")
        return refs

    # Tier 4: CWE fallback
    if finding.cwe:
        cwe_controls = _coerce_control_list(_load_cwe_fallback().get(_normalize_cwe(finding.cwe)))
        if cwe_controls:
            _add(cwe_controls, "cwe")

    return refs


def _normalize_control_id(raw: str | None) -> str:
    """Normalize a control id to OSCAL Token form ("ac-3", not "AC-3").

    Returns an empty string for None / blank / non-string input rather than
    raising, so a malformed YAML entry produces a single missing control
    rather than failing every lookup.
    """
    if not isinstance(raw, str):
        return ""
    return raw.strip().lower()


def _normalize_cwe(raw: str) -> str:
    """Normalize a CWE reference to ``CWE-<digits>``.

    Scanners are inconsistent: Bandit emits ``CWE-78``, some pipelines emit
    bare ``78`` or ``cwe-78``. Normalize all of them to the canonical form
    used as the mapping key so the lookup hits regardless of source.
    """
    s = raw.strip()
    if not s:
        return ""
    if s.upper().startswith("CWE-"):
        return "CWE-" + s[4:].lstrip("0") if s[4:] else s.upper()
    if s.isdigit():
        return f"CWE-{int(s)}"
    return s.upper()


def _coerce_control_list(raw: object) -> list[str]:
    """Accept either a string ("ac-3") or a list — always return a list.

    YAML lets a single-control entry be written without list syntax. The
    coercion keeps the data files readable and prevents the common authoring
    mistake (forgetting the leading ``-``) from producing a silent zero
    match.
    """
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, str)]
    return []


@lru_cache(maxsize=None)
def _load_scanner_mapping(scanner: str) -> dict:
    """Load ``mappings/<scanner>.yaml`` if present, else empty dict.

    Cached for the process lifetime — mapping files don't change between
    scans within one ``argus`` invocation. Tests reset via
    ``_reset_cache_for_tests``.

    Missing or unreadable mapping files are not an error: the scanner simply
    has no rule-level mappings yet, and resolution falls through to the CWE
    fallback. A YAML parse error is logged loudly because that's almost
    certainly a bug in the data file.
    """
    if not scanner:
        return {}
    path = _MAPPING_ROOT / f"{scanner}.yaml"
    return _load_yaml_dict(path)


@lru_cache(maxsize=1)
def _load_cwe_fallback() -> dict:
    return _load_yaml_dict(_MAPPING_ROOT / _CWE_FALLBACK_FILENAME)


def _load_yaml_dict(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        logger.warning("control_mapping: failed to parse %s: %s", path, exc)
        return {}
    if not isinstance(data, dict):
        logger.warning("control_mapping: %s is not a YAML mapping; ignoring", path)
        return {}
    return data


def _reset_cache_for_tests() -> None:
    """Drop cached YAML so the next call rereads from disk.

    Tests that monkeypatch ``_MAPPING_ROOT`` or write fixtures under a tmp
    path call this in setup/teardown so each test sees a fresh load.
    """
    _load_scanner_mapping.cache_clear()
    _load_cwe_fallback.cache_clear()


def mapping_root() -> Path:
    """Expose the on-disk mappings directory for tests + the CLI.

    Returned as a ``Path`` so callers can list, read, or stat individual
    mapping files without hard-coding the location. Tests monkeypatch the
    module attribute directly when they need to point lookups at a tmp dir.
    """
    return _MAPPING_ROOT
