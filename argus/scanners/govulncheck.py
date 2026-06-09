"""govulncheck — reachability-aware Go vulnerability scanner.

Where grype/trivy (container scanner) and osv-scanner report *every*
known vulnerability in *every* dependency present in a Go module's graph,
``govulncheck`` builds the program call graph from source and reports a
vulnerability **only when the vulnerable symbol is actually reachable**
from the code being scanned. That reachability filter is the whole point:
it removes the large class of "the vulnerable package is in go.mod but the
affected function is never called" false positives that presence-based
scanners surface (and that maintainers, rightly, find annoying).

Two finding tiers come out of a govulncheck run:

* **Called / reachable** — govulncheck found a call path to the
  vulnerable symbol. These are the actionable findings; they keep their
  real (OSV-derived) severity.
* **Imported, not called** — the vulnerable module/package is in the
  build graph but no call to the affected symbol was found. These are
  emitted as ``INFO`` with ``metadata["reachable"] = False`` so they
  stay visible for audit without tripping severity gates. (They never
  reach a severity threshold, so they can't fail a build — they're
  transparency, not noise.)

govulncheck emits a **stream of concatenated JSON objects** (not a single
document) on stdout — ``config``, ``progress``, ``osv`` (the vulnerability
records) and ``finding`` (per-vuln traces) messages. We decode the stream
with a raw JSON decoder loop, correlate each ``finding`` back to its
``osv`` record by id, and collapse the per-level findings for one vuln
into a single Finding.

Source mode (``govulncheck ./...``) is what gives symbol-level
reachability, and it resolves the ``./...`` pattern against the *current
working directory*. Locally we set ``cwd`` to the scan path; in the
container the image's ``WORKDIR /workspace`` provides the same anchor.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.scanner_template import ScanPaths, run_subprocess_scan
from argus.core.version import parse_tool_version


class GovulncheckScanner:
    """Wraps govulncheck to scan Go modules for *reachable* vulnerabilities."""

    name = "govulncheck"
    description = (
        "Reachability-aware Go vulnerability scanner — reports vulns whose "
        "affected symbol is actually called (cuts presence-based false positives)"
    )
    category = "sca"
    languages = ["go"]
    container_image = get_image("govulncheck")
    # The custom argus image declares ENTRYPOINT ["govulncheck"]; the
    # engine drops argv[0] for ENTRYPOINT-based images.
    container_entrypoint = "govulncheck"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run govulncheck against the Go module at *path*.

        ``cwd=path`` is essential: ``govulncheck ./...`` resolves the
        package pattern against the working directory, so the scan must
        run *inside* the target module rather than in argus's own CWD.
        The container path gets the same anchor from ``WORKDIR /workspace``
        baked into the image, so ``build_args`` can emit the same relative
        pattern for both execution modes.
        """
        return run_subprocess_scan(self, path, config, cwd=path)

    def build_args(self, paths: ScanPaths, config: dict) -> list[str]:
        """Build the full argv (including the binary name).

        govulncheck has no ``-o``/output-file flag — it streams JSON to
        stdout, which both the subprocess template and the engine's
        container path capture into the results file. The package pattern
        is relative (``./...``) so it resolves against the working
        directory (local ``cwd`` / container ``WORKDIR /workspace``)
        instead of an absolute mount path that govulncheck's package
        loader wouldn't accept.
        """
        # ``scan_target`` lets a caller narrow to a sub-package
        # (e.g. ``./cmd/...``); default is the whole module.
        scan_target = config.get("scan_target") or "./..."
        return ["govulncheck", "-json", scan_target]

    def is_available(self) -> bool:
        """Check if govulncheck is installed locally."""
        return shutil.which("govulncheck") is not None

    def install_command(self) -> str | None:
        """Return the install command for govulncheck."""
        return "go install golang.org/x/vuln/cmd/govulncheck@latest"

    def tool_version(self) -> str | None:
        """Return the installed govulncheck version, or None if unavailable.

        ``govulncheck -version`` prints multiple lines; the one we want
        looks like ``Scanner: govulncheck@v1.1.4``.
        """
        if not self.is_available():
            return None
        return parse_tool_version(
            ["govulncheck", "-version"], r"govulncheck@v?(\S+)",
        )

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse govulncheck's JSON-stream output into findings.

        The output is a sequence of concatenated JSON objects, so a single
        ``json.loads`` won't work — we decode them one at a time. Then we
        correlate ``finding`` messages with their ``osv`` records and emit
        one Finding per vulnerability, tagged with whether the vulnerable
        symbol was actually reachable.
        """
        text = raw_output_path.read_text(encoding="utf-8", errors="replace")
        osv_entries: dict[str, dict] = {}
        findings_by_osv: dict[str, list[dict]] = {}

        for msg in self._iter_json_stream(text):
            if "osv" in msg and isinstance(msg["osv"], dict):
                entry = msg["osv"]
                osv_id = entry.get("id")
                if osv_id:
                    osv_entries[osv_id] = entry
            elif "finding" in msg and isinstance(msg["finding"], dict):
                finding = msg["finding"]
                osv_id = finding.get("osv")
                if osv_id:
                    findings_by_osv.setdefault(osv_id, []).append(finding)

        results: list[Finding] = []
        for osv_id, group in findings_by_osv.items():
            reachable = any(self._is_reachable(f) for f in group)
            entry = osv_entries.get(osv_id, {})
            results.append(
                self._build_finding(osv_id, group, entry, reachable)
            )
        return results

    @staticmethod
    def _iter_json_stream(text: str):
        """Yield each JSON object from a stream of concatenated objects.

        govulncheck pretty-prints each message and concatenates them, so
        we use a raw decoder and advance past the whitespace between
        objects. A malformed/truncated stream raises ``JSONDecodeError``,
        which the template surfaces as ``parse_failed`` (a distinct state
        from "ran clean") rather than silently dropping findings.
        """
        decoder = json.JSONDecoder()
        idx = 0
        length = len(text)
        while idx < length:
            # Skip inter-object whitespace.
            while idx < length and text[idx] in " \t\r\n":
                idx += 1
            if idx >= length:
                break
            obj, end = decoder.raw_decode(text, idx)
            idx = end
            if isinstance(obj, dict):
                yield obj

    @staticmethod
    def _is_reachable(finding: dict) -> bool:
        """True when the vulnerable symbol is actually called.

        govulncheck's ``trace`` is ordered from the vulnerable symbol
        (index 0) outward to the entry point. A trace whose innermost
        frame names a ``function`` means govulncheck found a call path to
        the affected symbol — the finding is reachable. Module/package-only
        traces (no ``function``) mean the dependency is present but the
        affected code isn't called.
        """
        trace = finding.get("trace") or []
        return bool(trace and isinstance(trace[0], dict) and trace[0].get("function"))

    def _build_finding(
        self, osv_id: str, group: list[dict], entry: dict, reachable: bool,
    ) -> Finding:
        """Construct a single Finding for one vulnerability id."""
        # Prefer a reachable finding for the representative trace so the
        # call-site metadata reflects the actual call path.
        rep = next(
            (f for f in group if self._is_reachable(f)), group[0],
        )
        trace = rep.get("trace") or []
        vuln_frame = trace[0] if trace and isinstance(trace[0], dict) else {}

        package = vuln_frame.get("package") or vuln_frame.get("module") or ""
        module = vuln_frame.get("module") or ""
        pkg_version = vuln_frame.get("version") or ""
        location = f"{package}@{pkg_version}" if package else None

        summary = entry.get("summary") or entry.get("details") or osv_id
        if reachable:
            severity = self._extract_severity(entry)
            title = summary
        else:
            # Present but not called — keep it visible but un-gated.
            severity = Severity.INFO
            title = f"[imported, not called] {summary}"

        return Finding(
            id=osv_id,
            severity=severity,
            title=title,
            description=entry.get("details") or summary,
            location=location,
            cve=self._extract_cve(entry),
            scanner=self.name,
            metadata={
                "tool": "govulncheck",
                "reachable": reachable,
                "module": module,
                "package": package,
                "installed_version": pkg_version,
                "fixed_version": rep.get("fixed_version", ""),
                "vulnerable_symbol": self._symbol_name(vuln_frame),
                "aliases": entry.get("aliases", []),
                "call_stack": self._call_stack(trace) if reachable else [],
                "details_url": f"https://pkg.go.dev/vuln/{osv_id}",
            },
        )

    @staticmethod
    def _symbol_name(frame: dict) -> str:
        """Render ``receiver.function`` (or ``function``) for a trace frame."""
        func = frame.get("function") or ""
        recv = frame.get("receiver") or ""
        if func and recv:
            return f"{recv}.{func}"
        return func

    @classmethod
    def _call_stack(cls, trace: list) -> list[str]:
        """Compact, human-readable call stack for reachable findings.

        Ordered entry-point → vulnerable symbol (we reverse govulncheck's
        innermost-first ordering) so it reads like a stack trace.
        """
        frames = []
        for frame in reversed(trace):
            if not isinstance(frame, dict):
                continue
            sym = cls._symbol_name(frame)
            pkg = frame.get("package") or frame.get("module") or ""
            label = f"{pkg}.{sym}" if (pkg and sym) else (sym or pkg)
            pos = frame.get("position")
            if isinstance(pos, dict) and pos.get("filename"):
                label += f" ({pos['filename']}:{pos.get('line', 0)})"
            if label:
                frames.append(label)
        return frames

    @staticmethod
    def _extract_severity(entry: dict) -> Severity:
        """Map an OSV record's severity to the argus scale.

        Go advisory (``GO-YYYY-NNNN``) OSV entries frequently carry no
        machine-readable severity, in which case this returns
        ``UNKNOWN`` — that's a known limitation of the Go vuln DB, not a
        parse bug. When present, ``database_specific.severity`` is the
        most reliable field.
        """
        ds = entry.get("database_specific")
        if isinstance(ds, dict) and ds.get("severity"):
            return Severity.from_string(str(ds["severity"]))
        return Severity.UNKNOWN

    @staticmethod
    def _extract_cve(entry: dict) -> str | None:
        """Return the first ``CVE-*`` alias from the OSV record, if any."""
        for alias in entry.get("aliases") or []:
            if isinstance(alias, str) and alias.startswith("CVE-"):
                return alias
        return None
