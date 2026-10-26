"""OSV-Scanner dependency vulnerability scanner."""

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.scanner_template import ScanPaths, run_subprocess_scan, workspace_file
from argus.core.version import parse_tool_version


class OsvScanner:
    """Wraps OSV-Scanner to detect vulnerable dependencies."""

    name = "osv"
    description = "Dependency vulnerability scanner — checks lockfiles or an SBOM against the OSV database"
    category = "sca"
    languages = ["all"]
    container_image = get_image("osv-scanner")
    supports_sbom = True
    # The official osv-scanner image uses ENTRYPOINT ["/osv-scanner"]
    # — note the absolute path. ``$PATH`` inside the image does NOT
    # resolve a bare ``osv-scanner``; ``--entrypoint osv-scanner``
    # would exit 127. Pass the absolute path explicitly. Engine strips
    # argv[0] for ENTRYPOINT-based images so the binary name in
    # build_args() is informational only.
    container_entrypoint = "/osv-scanner"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run OSV-Scanner against the given path and return results."""
        return run_subprocess_scan(self, path, config)

    def build_args(self, paths: ScanPaths, config: dict) -> list[str]:
        """Build the full argv (including the binary name).

        Engine drops argv[0] when the container image declares an
        ENTRYPOINT, so the same method works for both local and
        container execution.

        Two modes:
        - SBOM mode (``config["sbom_path"]`` set): passes the SBOM via
          ``-L`` to ``scan`` (osv-scanner v2 API).
        - Source mode (default): passes the workspace path to
          ``scan source``, with optional ``-L <lockfile>`` and
          ``--recursive``.
        """
        sbom_path = config.get("sbom_path")
        if sbom_path:
            # The engine sets ``sbom_mount_path`` for container execution
            # (it mounts the host SBOM into a known container path).
            # Otherwise: absolute SBOM paths pass through; relative ones
            # resolve against the workspace.
            mount_path = config.get("sbom_mount_path")
            if mount_path:
                sbom_in_context = mount_path
            elif sbom_path.startswith("/"):
                sbom_in_context = sbom_path
            else:
                sbom_in_context = f"{paths.workspace}/{sbom_path}"
            return [
                "osv-scanner",
                "scan",
                "--format", "json",
                "--output-file", paths.output,
                "-L", sbom_in_context,
            ]

        args = [
            "osv-scanner",
            "scan", "source",
            "--format", "json",
            "--output-file", paths.output,
        ]
        lockfile = config.get("lockfile")
        if lockfile:
            args.extend(["-L", f"{paths.workspace}/{lockfile}"])
        else:
            recursive = config.get("recursive", True)
            if str(recursive).lower() not in ("false", "0", "no"):
                args.append("--recursive")
            args.append(paths.workspace)
        if config.get("config_file"):
            args.extend(["--config", workspace_file(paths.workspace, config["config_file"])])
        return args

    def is_available(self) -> bool:
        """Check if OSV-Scanner is installed."""
        return shutil.which("osv-scanner") is not None

    def install_command(self) -> str | None:
        """Return install command for OSV-Scanner."""
        return "Install from https://github.com/google/osv-scanner"

    def tool_version(self) -> str | None:
        """Return the installed OSV-Scanner version, or None if not available."""
        if not self.is_available():
            return None
        return parse_tool_version(
            ["osv-scanner", "--version"],
            r"v?(\d+\.\d+(?:\.\d+)?[\w.-]*)",
        )

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse OSV-Scanner JSON output into findings."""
        text = raw_output_path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            return []

        data = json.loads(text)
        findings = []

        for source_result in data.get("results", []):
            source_path = source_result.get("source", {}).get("path", "")

            for package_entry in source_result.get("packages", []):
                pkg_info = package_entry.get("package", {})
                pkg_name = pkg_info.get("name", "")
                pkg_version = pkg_info.get("version", "")
                pkg_ecosystem = pkg_info.get("ecosystem", "")

                for records in self._alias_groups(package_entry):
                    finding = self._parse_vulnerability(
                        records, source_path, pkg_name, pkg_version, pkg_ecosystem
                    )
                    findings.append(finding)

        return findings

    def _alias_groups(self, package_entry: dict) -> list[list[dict]]:
        """The package's vulnerability records, one list per distinct advisory.

        OSV keeps a record per database that published an advisory (a PyPI
        package often has both a GHSA and a PYSEC record for one bug), and
        osv-scanner reports every record but names the aliases in ``groups``.
        Each list holds the reported records of one group, primary first; a
        record no group names stands alone. Lists come in the order their
        first record was reported.
        """
        vulns = package_entry.get("vulnerabilities", [])
        by_id = {vuln.get("id"): vuln for vuln in vulns}
        group_of: dict[str, list[dict]] = {}
        for group in package_entry.get("groups") or []:
            members = [by_id[vid] for vid in group.get("ids", []) if vid in by_id]
            for member in members:
                group_of.setdefault(member.get("id"), members)

        grouped: list[list[dict]] = []
        emitted: set[str] = set()
        for vuln in vulns:
            if vuln.get("id") in emitted:
                continue
            members = group_of.get(vuln.get("id"), [vuln])
            members = [m for m in members if m.get("id") not in emitted]
            emitted.update(m.get("id") for m in members)
            grouped.append(sorted(members, key=self._primary_rank))
        return grouped

    def _primary_rank(self, vuln: dict) -> tuple[bool, str]:
        """Sort key that puts an advisory's GHSA record first, then by id.

        GitHub's records carry the reviewed severity and CWE, and a GHSA id is
        what findings for these packages were already named by, so keys built
        on the finding id do not move.
        """
        vid = str(vuln.get("id", ""))
        return (not vid.startswith("GHSA-"), vid)

    def _parse_vulnerability(
        self,
        records: list[dict],
        source_path: str,
        pkg_name: str,
        pkg_version: str,
        pkg_ecosystem: str,
    ) -> Finding:
        """Convert one advisory's OSV records (primary first) into a Finding.

        The primary record names the finding. Severity is the highest any
        record reports, so a PYSEC record with no severity never downgrades
        its GHSA alias; CVE, CWE, summary and fix fall back to the aliases.
        """
        primary_id = records[0].get("id", "UNKNOWN")
        aliases = []
        for record in records:
            for alias in (record.get("id"), *record.get("aliases", [])):
                if alias and alias != primary_id and alias not in aliases:
                    aliases.append(alias)
        summary = self._first(records, lambda record: record.get("summary"))

        return Finding(
            id=primary_id,
            severity=max(self._extract_severity(record) for record in records),
            title=summary or "Unknown vulnerability",
            description=summary or "",
            location=source_path or None,
            cve=self._first(records, self._extract_cve),
            cwe=self._first(records, self._extract_cwe),
            scanner=self.name,
            metadata={
                "package_name": pkg_name,
                "package_version": pkg_version,
                "ecosystem": pkg_ecosystem,
                "aliases": aliases,
                "fixed_version": self._first(records, self._extract_fixed_version),
                **self._advisory_modified(records),
            },
        )

    def _advisory_modified(self, records: list[dict]) -> dict[str, str]:
        """``{"advisory_modified": ...}``: the newest ``modified`` across the records.

        osv-scanner asks osv.dev at scan time, so its results move whenever an
        advisory is published or edited (OSV bumps ``modified`` on any change,
        affected versions included). A consumer comparing two scans uses this to
        tell an advisory that changed after its baseline ran from a dependency the
        change added. Taken across the alias group, so a PYSEC copy edited after
        its GHSA twin still counts. osv.dev's own string is kept; times are only
        parsed to pick the newest. Empty when no record carries a usable one.
        """
        newest: tuple[datetime, str] | None = None
        for record in records:
            raw = record.get("modified")
            try:
                parsed = datetime.fromisoformat(raw)
            except (TypeError, ValueError):
                continue
            if parsed.tzinfo is None:  # OSV writes UTC; never compare naive with aware
                parsed = parsed.replace(tzinfo=timezone.utc)
            if newest is None or parsed > newest[0]:
                newest = (parsed, raw)
        return {"advisory_modified": newest[1]} if newest else {}

    def _first(self, records: list[dict], extract) -> str | None:
        """The first non-empty value ``extract`` returns across ``records``."""
        for record in records:
            value = extract(record)
            if value:
                return value
        return None

    def _extract_fixed_version(self, vuln: dict) -> str | None:
        """The upstream-fixed version for this vuln, if OSV reports one.

        OSV records fixes as ``affected[].ranges[].events[]`` entries carrying a
        ``fixed`` key. Return the first fixed version found; ``None`` means no
        upstream fix is published yet — consumers use this to avoid grading an
        unpatchable-upstream CVE like negligence (fix-aware grading).
        """
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    fixed = event.get("fixed")
                    if fixed:
                        return str(fixed)
        return None

    def _extract_severity(self, vuln: dict) -> Severity:
        """Extract severity from database_specific or affected blocks."""
        db_specific = vuln.get("database_specific", {})
        raw_severity = db_specific.get("severity", "")
        if raw_severity:
            return Severity.from_string(raw_severity)

        # Fall back to affected[].database_specific.severity
        for affected in vuln.get("affected", []):
            affected_db = affected.get("database_specific", {})
            raw_severity = affected_db.get("severity", "")
            if raw_severity:
                return Severity.from_string(raw_severity)

        return Severity.UNKNOWN

    def _extract_cve(self, vuln: dict) -> str | None:
        """Extract the first CVE alias from the vulnerability."""
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                return alias
        return None

    def _extract_cwe(self, vuln: dict) -> str | None:
        """Extract the first CWE from database_specific.cwe_ids."""
        cwe_ids = vuln.get("database_specific", {}).get("cwe_ids", [])
        if cwe_ids:
            return cwe_ids[0]
        return None
