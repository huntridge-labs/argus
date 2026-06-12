"""OpenVEX reporter — consolidated Vulnerability Exploitability eXchange output.

Spike (issue #229). Emits ONE OpenVEX v0.2.0 document per scan, keyed by the
PURL of each vulnerable component, built from the already-normalized component
findings (PURL + CVE) the container / SCA scanners produce (trivy, grype, osv,
container). This serializes at the Argus normalization tier rather than per
scanner, so a single Argus-wide document covers every SCA source.

SAST / IaC / secrets / DAST findings have no VEX vocabulary and are excluded by
construction: a statement is emitted only for a finding that carries a CVE *and*
resolves to a component identifier (PURL).

Default statement status is ``affected`` — the scanner confirmed a vulnerable
component is present, the ground-truth baseline onto which a downstream triage
source (AutoGRC / AutoISSO decision capture, a manual override file) overlays
``not_affected`` / ``fixed`` decisions. Sourcing those decisions, and wiring an
override into the reporter, is the open design question tracked in #229 and is
deliberately out of scope for the prototype.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.core.models import Finding, ScanSummary

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
_DEFAULT_OUTPUT_DIR = Path("./argus-results")
# A scanner-detected vulnerable component is, by definition, present and
# vulnerable — "affected" in VEX terms. not_affected / fixed are human/triage
# decisions layered on top (see module docstring + #229).
_DEFAULT_STATUS = "affected"

# OSV ecosystem -> purl type, for synthesizing a PURL when the scanner did not
# emit one directly. Unknown ecosystems fall back to a lowercased token, which
# is still a usable (if non-canonical) purl type.
_ECOSYSTEM_TO_PURL_TYPE = {
    "PyPI": "pypi", "npm": "npm", "Go": "golang", "Maven": "maven",
    "RubyGems": "gem", "crates.io": "cargo", "NuGet": "nuget",
    "Packagist": "composer", "Pub": "pub", "Hex": "hex", "Debian": "deb",
    "Alpine": "apk",
}


class OpenVexReporter:
    """Emit a consolidated OpenVEX document for component-CVE findings."""

    def report(self, summary: ScanSummary, output_dir: Optional[Path] = None) -> Path:
        """Write ``output_dir/argus-results.openvex.json`` and return its path."""
        dest = Path(output_dir) if output_dir else _DEFAULT_OUTPUT_DIR
        dest.mkdir(parents=True, exist_ok=True)
        filepath = dest / "argus-results.openvex.json"
        filepath.write_text(
            json.dumps(self._build(summary), indent=2) + "\n", encoding="utf-8",
        )
        return filepath

    def _build(self, summary: ScanSummary) -> dict:
        statements = self._statements(summary)
        # Deterministic @id derived from the statement content: re-running the
        # same scan yields the same document id, so artifacts are idempotent
        # and diffable. (The timestamp is the only non-deterministic field.)
        digest = hashlib.sha256(
            json.dumps(statements, sort_keys=True).encode("utf-8"),
        ).hexdigest()[:16]
        return {
            "@context": OPENVEX_CONTEXT,
            "@id": f"https://huntridge-labs.github.io/argus/vex/{digest}",
            "author": "Argus",
            "role": "Document Creator",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": 1,
            "statements": statements,
        }

    def _statements(self, summary: ScanSummary) -> list[dict]:
        # Dedup by (CVE, product): the same vulnerable component is commonly
        # reported by more than one scanner or across multiple targets.
        seen: dict[tuple[str, str], dict] = {}
        for result in summary.results:
            for finding in result.findings:
                if not finding.cve:
                    continue
                product = self._product_id(finding)
                if not product:
                    continue
                key = (finding.cve, product)
                if key not in seen:
                    seen[key] = {
                        "vulnerability": {"name": finding.cve},
                        "products": [{"@id": product}],
                        "status": _DEFAULT_STATUS,
                    }
        return [seen[k] for k in sorted(seen)]

    @staticmethod
    def _product_id(finding: Finding) -> str:
        """VEX product identifier for a finding — its PURL when the scanner
        provided one, else a best-effort PURL synthesized from the package
        metadata (covers OSV, which carries ecosystem + name + version)."""
        meta = finding.metadata or {}
        purl = (meta.get("purl") or "").strip()
        if purl:
            return purl
        name = (meta.get("package") or meta.get("package_name") or "").strip()
        if not name:
            return ""
        version = (
            meta.get("installed_version") or meta.get("package_version") or ""
        ).strip()
        ecosystem = (meta.get("ecosystem") or "").strip()
        purl_type = _ECOSYSTEM_TO_PURL_TYPE.get(ecosystem, ecosystem.lower() or "generic")
        base = f"pkg:{purl_type}/{name}"
        return f"{base}@{version}" if version else base
