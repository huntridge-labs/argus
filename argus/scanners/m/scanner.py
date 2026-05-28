"""MScanner — Argus scanner module for MUMPS / M language sources.

Wraps the rule registry under the ``Scanner`` protocol so the engine can
invoke it like any other SAST scanner. Execution model: pure Python
inside the host process when ``py-tree-sitter`` and the compiled grammar
are present; the engine routes to the ``scanner-m`` container image
otherwise (mirrors the bandit / gitleaks fallback path).

The scanner walks ``path`` for files matching ``DEFAULT_EXTENSIONS``,
parses each via :class:`MParser`, and runs every entry in
``argus.scanners.m.rules.RULES`` against the parse tree. Findings are
emitted with ``scanner="m"`` and an id from the rule (``M001``, ...).
"""

from __future__ import annotations

from pathlib import Path

from argus.core.models import Finding, ScanResult

from .parser import GrammarUnavailable, MParser, tree_sitter_available
from .rules import RULES


# MUMPS source files in the wild use ``.m``, ``.mac`` (Caché macro),
# ``.int`` (Caché intermediate). We default to ``.m`` for Phase 1; the
# Caché-specific extensions get added in Phase 2 alongside ObjectScript
# dialect support.
DEFAULT_EXTENSIONS = (".m",)


class MScanner:
    """SAST scanner for MUMPS / M language source files."""

    name = "m"
    description = (
        "MUMPS / M language SAST. Detects XECUTE injection, indirection "
        "injection, hard-coded credentials in globals, and structural "
        "diagnostics."
    )
    category = "sast"
    languages = ["mumps"]
    # Container image registration is wired up in a follow-up commit once
    # ``scanner-m`` is published to ghcr.io. ``is_available()`` gates
    # local execution until then. The image's ENTRYPOINT runs
    # ``python -m argus`` so ``build_args`` only supplies the
    # ``scan m ...`` portion (the engine strips argv[0]).
    container_image = ""
    container_entrypoint = "argus"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Walk ``path`` for MUMPS sources, parse each, run every rule.

        Two-phase loop: first pre-parse every ``.m`` file in the scan
        path, then build the cross-file call graph, then run each rule
        with the graph available via ``config['_callgraph']``. The
        pre-parse pass adds one parse per file but lets every rule see
        cross-routine context for free.
        """
        config = config or {}
        extensions = tuple(config.get("extensions", DEFAULT_EXTENSIONS))
        findings: list[Finding] = []
        files_scanned = 0
        parse_failures = 0

        target = Path(path)
        if not target.exists():
            return ScanResult(
                scanner=self.name,
                findings=[],
                metadata={"error": f"path does not exist: {path}"},
            )

        # Phase 1: parse every source. Collect ParsedSource handles
        # along with their original path so we can dispatch findings
        # per file later.
        parsed_units: list[tuple[Path, object]] = []
        for source_path in self._iter_sources(target, extensions):
            files_scanned += 1
            try:
                source_bytes = source_path.read_bytes()
                parsed = MParser.parse(source_path, source_bytes)
            except GrammarUnavailable:
                # Re-raise: callers (engine) know how to route this into
                # the container fallback path. Don't silently produce a
                # zero-findings result that looks like a clean scan.
                raise
            except OSError as exc:
                parse_failures += 1
                findings.append(self._parse_failure_finding(source_path, str(exc)))
                continue
            parsed_units.append((source_path, parsed))

        # Phase 2: build the cross-file call graph in a single
        # additional walk per source. Rules consume it via
        # config['_callgraph'] when they want cross-routine context.
        from .callgraph import build_callgraph
        callgraph = build_callgraph(parsed for _, parsed in parsed_units)
        rule_config = dict(config)
        rule_config["_callgraph"] = callgraph

        # Phase 3: run each rule against each parsed source.
        for source_path, parsed in parsed_units:
            for rule in RULES:
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
                findings.extend(rule_findings)

        return ScanResult(
            scanner=self.name,
            findings=findings,
            metadata={
                "files_scanned": files_scanned,
                "parse_failures": parse_failures,
                "rules_run": [r.id for r in RULES],
                "callgraph": {
                    "routines": len(callgraph.routines),
                    "edges": len(callgraph.edges),
                },
            },
        )

    def build_args(self, paths, config: dict | None = None) -> list[str]:
        """Container argv for ``argus scan m`` inside ``scanner-m``.

        The image's ENTRYPOINT is ``["python", "-m", "argus"]`` so this
        method supplies ``scan m --path ... --output-dir ...`` after the
        engine strips argv[0]. Honoured by the standard scanner_template
        once ``container_image`` is wired up in a follow-up commit;
        until then the method exists to satisfy the
        ``test_all_scanners_have_container_args`` contract.
        """
        from pathlib import PurePosixPath
        config = config or {}
        output_dir = str(PurePosixPath(paths.output).parent) if paths.output else "/output"
        args = [
            "argus", "scan", "m",
            "--path", paths.workspace,
            "--output-dir", output_dir,
            "--format", "json",
        ]
        extra = config.get("extra_args")
        if extra:
            args.extend(str(a) for a in extra)
        return args

    def is_available(self) -> bool:
        """True when py-tree-sitter + the compiled grammar are reachable."""
        return tree_sitter_available()

    def install_command(self) -> str | None:
        """Hint the user how to enable local execution."""
        return (
            "pip install argus-security[m] && "
            "scripts/build-m-grammar.sh  "
            "# or use the scanner-m container image"
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


def _severity_override(rule, config: dict | None):
    """Resolve ``scanners.m.rules.<id>.severity`` from the config into
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
