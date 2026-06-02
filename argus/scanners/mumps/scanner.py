"""MumpsScanner — Argus scanner module for MUMPS / M language sources.

Wraps the rule registry under the ``Scanner`` protocol so the engine can
invoke it like any other SAST scanner. Execution model: pure Python
inside the host process when ``py-tree-sitter`` and the compiled grammar
are present; the engine routes to the ``scanner-mumps`` container image
otherwise (mirrors the bandit / gitleaks fallback path).

The scanner walks ``path`` for files matching ``DEFAULT_EXTENSIONS``,
parses each via :class:`MumpsParser`, and runs every entry in
``argus.scanners.mumps.rules.RULES`` against the parse tree. Findings are
emitted with ``scanner="mumps"`` and an id from the rule (``M001``, ...).
"""

from __future__ import annotations

import re
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult

from .parser import GrammarUnavailable, MumpsParser, tree_sitter_available
from .rules import RULES
from .taint import collect_tainted_variables


# MUMPS source files in the wild use ``.m``, ``.mac`` (Caché macro),
# ``.int`` (Caché intermediate). We default to ``.m`` for Phase 1; the
# Caché-specific extensions get added in Phase 2 alongside ObjectScript
# dialect support.
DEFAULT_EXTENSIONS = (".m",)


class MumpsScanner:
    """SAST scanner for MUMPS / M language source files."""

    name = "mumps"
    description = (
        "MUMPS / M language SAST. Detects XECUTE injection, indirection "
        "injection, hard-coded credentials in globals, and structural "
        "diagnostics."
    )
    category = "sast"
    languages = ["mumps"]
    # ``scanner-mumps`` is published to ghcr.io, so the engine routes
    # here (backend auto/docker) when the local grammar is absent, giving
    # zero-toolchain execution. The image's ENTRYPOINT runs
    # ``python -m argus`` so ``build_args`` only supplies the
    # ``scan mumps ...`` portion (the engine strips argv[0]).
    container_image = get_image("mumps")
    container_entrypoint = "argus"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Walk ``path`` for MUMPS sources, parse each, run every rule.

        Streaming two-pass loop, bounded to one parse tree resident at a
        time:

        * **Pass A** parses each file, extracts lightweight call-graph
          facts (labels + cross-routine edges, all strings), and drops
          the tree. The cross-file call graph is built from those facts.
        * **Pass B** re-parses each file on demand, runs every enabled
          rule (with the call graph available via ``config['_callgraph']``
          and the per-file taint set via ``config['_tainted']``), and
          drops the tree.

        Re-parsing each file twice costs a few percent of wall time but
        keeps peak memory flat regardless of corpus size — the earlier
        parse-everything-first design held every tree resident and
        exhausted RAM on large corpora.
        """
        config = config or {}
        extensions = tuple(config.get("extensions", DEFAULT_EXTENSIONS))
        findings: list[Finding] = []
        files_scanned = 0
        parse_failures = 0
        suppressed_count = 0

        target = Path(path)
        if not target.exists():
            return ScanResult(
                scanner=self.name,
                findings=[],
                metadata={"error": f"path does not exist: {path}"},
            )

        from .callgraph import build_callgraph_from_facts, extract_facts

        source_paths = list(self._iter_sources(target, extensions))
        ip_enabled, ip_max_depth = _interproc_settings(config)

        # Pass A — extract lightweight call-graph facts per file, then
        # drop each parse tree before moving to the next file. Holding
        # only the facts (labels + cross-routine edges, all strings)
        # keeps resident memory at one tree at a time instead of every
        # file's tree at once, which is what previously exhausted RAM on
        # large corpora (a routine name index, not a tree pile).
        facts = []
        local_taint: dict[str, set[str]] = {}
        for source_path in source_paths:
            try:
                parsed = MumpsParser.parse(source_path, source_path.read_bytes())
            except GrammarUnavailable:
                # Re-raise: callers (engine) route this into the
                # container fallback path rather than reporting a clean
                # zero-findings scan.
                raise
            except OSError:
                # Read/parse failure is reported authoritatively in
                # Pass B (which counts files_scanned / parse_failures).
                continue
            facts.append(extract_facts(parsed))
            if ip_enabled:
                # Per-routine local taint feeds the propagation pass.
                local_taint[Path(source_path).stem.upper()] = (
                    collect_tainted_variables(parsed, config)
                )
            del parsed  # release the tree before the next file

        callgraph = build_callgraph_from_facts(facts)
        rule_config = dict(config)
        rule_config["_callgraph"] = callgraph
        active_rules = [r for r in RULES if _rule_enabled(r, config)]

        # Inter-procedural taint (opt-in): propagate each caller's local
        # taint one hop into its callees' formal parameters.
        inbound_taint: dict[str, set[str]] = {}
        if ip_enabled:
            from .interproc import propagate_inbound_taint
            inbound_taint = propagate_inbound_taint(
                callgraph, local_taint, ip_max_depth,
            )

        # Pass B — re-parse each file on demand, run the rules, drop the
        # tree. The extra parse adds a few percent of wall time; the
        # memory ceiling is what matters for whole-corpus scans.
        for source_path in source_paths:
            files_scanned += 1
            try:
                parsed = MumpsParser.parse(source_path, source_path.read_bytes())
            except GrammarUnavailable:
                raise
            except OSError as exc:
                parse_failures += 1
                findings.append(self._parse_failure_finding(source_path, str(exc)))
                continue
            # Compute the tainted-variable set once per file and share it
            # via config so the four taint-sink rules don't each re-walk
            # the tree to recompute the identical set. When inter-
            # procedural analysis is on, union in the formals this
            # routine receives tainted from its callers.
            tainted = collect_tainted_variables(parsed, config)
            if ip_enabled:
                inbound = inbound_taint.get(Path(source_path).stem.upper())
                if inbound:
                    tainted = tainted | inbound
            rule_config["_tainted"] = tainted
            file_findings: list[Finding] = []
            for rule in active_rules:
                try:
                    rule_findings = list(rule.analyze(parsed, rule_config))
                except Exception as exc:  # noqa: BLE001
                    # Rule crash must not take down the whole scan;
                    # surface it as a finding so it's visible in output
                    # rather than disappearing into logs.
                    findings.append(self._rule_crash_finding(rule, source_path, exc))
                    continue
                override = _severity_override(rule, config)
                if override is not None:
                    rule_findings = _apply_severity_override(
                        rule_findings, rule.severity, override,
                    )
                file_findings.extend(rule_findings)
            # Honour inline ``;argus:ignore`` directives. Counted (not silently
            # dropped) so suppression is visible in scan metadata.
            supp = _suppression_map(parsed.source_text)
            if supp:
                kept: list[Finding] = []
                for finding in file_findings:
                    if _is_suppressed(finding, supp):
                        suppressed_count += 1
                    else:
                        kept.append(finding)
                file_findings = kept
            findings.extend(file_findings)
            del parsed  # release this file's tree before the next

        return ScanResult(
            scanner=self.name,
            findings=findings,
            metadata={
                "files_scanned": files_scanned,
                "parse_failures": parse_failures,
                "suppressed": suppressed_count,
                "rules_run": [r.id for r in active_rules],
                "callgraph": {
                    "routines": len(callgraph.routines),
                    "edges": len(callgraph.edges),
                },
            },
        )

    def build_args(self, paths, config: dict | None = None) -> list[str]:
        """Container argv for ``argus scan mumps`` inside ``scanner-mumps``.

        The image's ENTRYPOINT is ``["python", "-m", "argus"]`` so this
        method supplies ``scan mumps --path ... --output-dir ...`` after the
        engine strips argv[0]. Honoured by the engine's container path
        whenever ``container_image`` resolves (the published
        ``scanner-mumps`` image) and Docker is available.
        """
        from pathlib import PurePosixPath
        config = config or {}
        output_dir = str(PurePosixPath(paths.output).parent) if paths.output else "/output"
        args = [
            "argus", "scan", "mumps",
            "--path", paths.workspace,
            "--output-dir", output_dir,
            "--format", "json",
            # Flat output (no timestamped subdir) so the engine's
            # top-level glob of output_dir picks up argus-results.json.
            "--no-timestamp",
            # No registry / network work needed at scan time.
            "--no-update-check",
        ]
        extra = config.get("extra_args")
        if extra:
            args.extend(str(a) for a in extra)
        return args

    def parse_results(self, raw_output_path) -> list[Finding]:
        """Lift mumps findings out of a container run's JSON report.

        On the container path the engine runs ``argus scan mumps`` nested
        inside ``scanner-mumps``; that writes the standard Argus JSON
        report (``argus-results.json``), which the engine hands here. We
        rebuild the mumps findings as ``Finding`` objects. Local execution
        never calls this - it returns findings straight from ``scan()``.
        """
        import json

        from argus.core.models import Severity

        # ``argus scan`` writes two JSON files (argus-results.json plus the
        # argus-audit.json manifest). The engine hands us whichever its glob
        # saw first, so resolve to the results file in the same directory -
        # findings never live in the audit manifest.
        path = Path(raw_output_path)
        if path.name != "argus-results.json":
            sibling = path.parent / "argus-results.json"
            if sibling.exists():
                path = sibling
        data = json.loads(path.read_text(encoding="utf-8"))
        findings: list[Finding] = []
        for result in data.get("results", []):
            for raw in result.get("findings", []):
                if (raw.get("scanner") or result.get("scanner")) != self.name:
                    continue
                location = raw.get("location")
                # Strip the container mount prefix so locations read as
                # repo-relative rather than exposing the ``/workspace`` mount.
                if location and location.startswith("/workspace/"):
                    location = location[len("/workspace/"):]
                findings.append(
                    Finding(
                        id=raw.get("id", ""),
                        severity=Severity.from_string(raw.get("severity", "info")),
                        title=raw.get("title", ""),
                        description=raw.get("description", ""),
                        location=location,
                        cwe=raw.get("cwe"),
                        cve=raw.get("cve"),
                        scanner=self.name,
                        metadata=raw.get("metadata") or {},
                    )
                )
        return findings

    def is_available(self) -> bool:
        """True when py-tree-sitter + the compiled grammar are reachable."""
        return tree_sitter_available()

    def install_command(self) -> str | None:
        """Hint the user how to enable local execution."""
        return (
            "pip install argus-security[mumps] && "
            "scripts/build-mumps-grammar.sh  "
            "# or use the scanner-mumps container image"
        )

    def tool_version(self) -> str | None:
        """Return the py-tree-sitter version, or None when unavailable."""
        try:
            import tree_sitter  # type: ignore[import-not-found]
        except ImportError:
            return None
        return getattr(tree_sitter, "__version__", None)

    @staticmethod
    def _iter_sources(target: Path, extensions: tuple[str, ...]):
        """Yield every file under ``target`` matching one of ``extensions``."""
        if target.is_file():
            if target.suffix in extensions:
                yield target
            return
        for candidate in target.rglob("*"):
            if candidate.is_file() and candidate.suffix in extensions:
                yield candidate

    def _parse_failure_finding(self, source_path: Path, error: str) -> Finding:
        from argus.core.models import Severity
        return Finding(
            id="M-PARSE-FAIL",
            severity=Severity.LOW,
            title="MUMPS source could not be read",
            description=f"Failed to read {source_path}: {error}",
            location=str(source_path),
            scanner=self.name,
        )

    def _rule_crash_finding(self, rule, source_path: Path, exc: Exception) -> Finding:
        from argus.core.models import Severity
        return Finding(
            id="M-RULE-CRASH",
            severity=Severity.LOW,
            title=f"Rule {rule.id} crashed while analyzing source",
            description=(
                f"Rule {rule.id} raised {type(exc).__name__}: {exc}. "
                "Other rules continued. Please report this with a minimal "
                "reproducer at huntridge-labs/argus."
            ),
            location=str(source_path),
            scanner=self.name,
            metadata={"rule": rule.id, "error_type": type(exc).__name__},
        )


def _interproc_settings(config: dict | None) -> tuple[bool, int]:
    """Resolve ``scanners.mumps.interprocedural`` config.

    Returns ``(enabled, max_depth)``. Disabled by default so existing
    scans are byte-identical; ``max_depth`` defaults to 1 (one call hop)
    and is clamped to at least 1 when enabled.
    """
    block = (config or {}).get("interprocedural") or {}
    enabled = bool(block.get("enabled", False))
    try:
        max_depth = int(block.get("max_depth", 1))
    except (TypeError, ValueError):
        max_depth = 1
    return enabled, max(1, max_depth)


def _is_security_rule(rule) -> bool:
    """Security rules are the M00x family (M001-M006); the M1xx / M2xx
    families are diagnostics / lint."""
    return rule.id[:2].upper() == "M0"


def _rule_enabled(rule, config: dict | None) -> bool:
    """Resolve whether ``rule`` should run.

    Precedence: an explicit ``scanners.mumps.rules.<id>.enabled`` always
    wins. Otherwise a ``scanners.mumps.profile`` preset applies:

    * ``security-only`` — only the security rules that are on by default;
    * ``lint-only`` — only the diagnostics that are on by default;
    * ``strict`` — every rule, including the off-by-default ones;
    * ``default`` / unset — each rule's ``enabled_by_default``.

    Absent config preserves each rule's default, so existing setups are
    unchanged.
    """
    default = getattr(rule, "enabled_by_default", True)
    if not config:
        return default
    rule_cfg = (config.get("rules") or {}).get(rule.id) or {}
    if "enabled" in rule_cfg:
        return bool(rule_cfg["enabled"])
    profile = str(config.get("profile") or "").strip().lower()
    if profile == "strict":
        return True
    if profile == "security-only":
        return _is_security_rule(rule) and default
    if profile == "lint-only":
        return (not _is_security_rule(rule)) and default
    return default


_IGNORE_RE = re.compile(r";\s*argus:ignore(?:\[([^\]]*)\])?", re.IGNORECASE)


def _suppression_map(source_text: str) -> dict[int, set[str]]:
    """Map a 1-based line number to the set of rule ids an inline
    ``;argus:ignore`` directive silences on it, or ``{'*'}`` for all rules.

    ``;argus:ignore`` silences every finding on the line; ``;argus:ignore[M002]``
    or ``;argus:ignore[M002,M211]`` silences only the listed rules. A directive
    also covers the line immediately below it (so it can sit on its own line
    above the flagged statement)."""
    out: dict[int, set[str]] = {}
    for i, line in enumerate(source_text.splitlines(), start=1):
        match = _IGNORE_RE.search(line)
        if match is None:
            continue
        ids = match.group(1)
        out[i] = (
            {s.strip().upper() for s in ids.split(",") if s.strip()} if ids else {"*"}
        )
    return out


def _is_suppressed(finding, supp: dict[int, set[str]]) -> bool:
    """True when an inline ignore directive on the finding's line (or the
    line above it) covers the finding's rule id."""
    if not supp or not finding.location:
        return False
    try:
        line = int(finding.location.rsplit(":", 2)[1])
    except (IndexError, ValueError):
        return False
    for candidate in (line, line - 1):
        ids = supp.get(candidate)
        if ids and ("*" in ids or finding.id.upper() in ids):
            return True
    return False


def _severity_override(rule, config: dict | None):
    """Resolve ``scanners.mumps.rules.<id>.severity`` from the config into
    a Severity enum, or ``None`` when no override is configured.

    Unknown severity strings degrade gracefully — ``None`` is returned
    rather than aborting the scan on a typo.
    """
    if not config:
        return None
    rule_cfg = (config.get("rules") or {}).get(rule.id) or {}
    raw = rule_cfg.get("severity")
    if not raw:
        return None
    from argus.core.models import Severity
    resolved = Severity.from_string(str(raw))
    if resolved == Severity.UNKNOWN:
        return None
    return resolved


def _apply_severity_override(findings, default_severity, override):
    """Replace the severity on findings that fired at the rule's
    *default* severity.

    Per-finding precision (M003's PIPE bump to CRITICAL) is preserved:
    a finding whose severity already differs from the rule default is
    left untouched. Only the baseline severity is user-tunable.
    """
    import dataclasses
    out = []
    for finding in findings:
        if finding.severity == default_severity:
            out.append(dataclasses.replace(finding, severity=override))
        else:
            out.append(finding)
    return out
