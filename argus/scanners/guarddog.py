"""GuardDog scanner — malicious-package heuristics for dependency manifests.

GuardDog (Datadog, OSS) flags **malicious** packages — install-time code
execution, typosquatting, obfuscation, exfiltration, suspicious metadata — via
source-code (Semgrep) and metadata heuristics. That's a different signal from
the CVE-based SCA scanners (osv / grype / trivy): those answer "does a
dependency have a *known vulnerability*", GuardDog answers "does a dependency
look *malicious*". The two are complementary; this scanner covers the gap.

Execution model: local-binary (``guarddog`` on PATH; ``pip install guarddog``).
It has no bundled container image yet — running it in the dogfood CI image is a
follow-up (GuardDog depends on ``pygit2``/libgit2, which needs the base image to
carry the native lib). ``is_available`` / ``install_command`` gate it cleanly
until then, exactly like the other tool-backed scanners.

CVE-free by construction, so ``supports_vex`` is False; suppression is
GuardDog-native via ``--exclude-rules`` (see ``native_ignore``).

Secrets handling: GuardDog's source-code rule matches include a ``code``
excerpt of the flagged package's source. That excerpt is **never** copied into
a ``Finding`` — only the rule id, package, version, and location are surfaced —
so a malicious package's payload can't leak into ``argus-results.json``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from argus.core.models import Finding, ScanResult, Severity
from argus.core.version import parse_tool_version

# Manifest filename → GuardDog ecosystem keyword. GuardDog's ``verify``
# subcommand consumes the manifest directly for each ecosystem.
_MANIFESTS: dict[str, str] = {
    "requirements.txt": "pypi",
    "package.json": "npm",
    "go.mod": "go",
    "Gemfile.lock": "rubygems",
}

# Directories never worth walking for manifests (vendored / build output).
_SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", "site-packages",
}


class GuardDogScanner:
    """Run GuardDog against dependency manifests to flag malicious packages."""

    name = "guarddog"
    description = "Malicious-package heuristics (typosquat, install-hooks, obfuscation) for pip/npm/go/rubygems"
    category = "supply-chain"
    languages = ["python", "javascript", "go", "ruby"]
    container_image = ""  # local-exec only for now (see module docstring)
    supports_sbom = False
    supports_vex = False

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        config = config or {}
        root = Path(path)
        manifests = self._find_manifests(root)
        if not manifests:
            return ScanResult(
                scanner=self.name,
                metadata={"note": "no supported dependency manifests found (requirements.txt, package.json, go.mod, Gemfile.lock)"},
            )

        findings: list[Finding] = []
        errors: dict[str, str] = {}
        scanned: list[str] = []
        for manifest in manifests:
            ecosystem = _MANIFESTS[manifest.name]
            try:
                data = self._run_verify(ecosystem, manifest, config)
            except RuntimeError as exc:
                errors[str(manifest)] = str(exc)
                continue
            scanned.append(f"{ecosystem}:{manifest}")
            findings.extend(self.parse_verify(data, ecosystem, manifest))

        return ScanResult(
            scanner=self.name,
            findings=findings,
            metadata={"manifests_scanned": scanned, **({"errors": errors} if errors else {})},
        )

    def is_available(self) -> bool:
        return shutil.which("guarddog") is not None

    def install_command(self) -> str | None:
        return "pip install guarddog"

    def tool_version(self) -> str | None:
        if not self.is_available():
            return None
        return parse_tool_version(["guarddog", "--version"], r"(\d+\.\d+\.\d+)")

    def container_args(self, config: dict | None = None) -> list[str]:
        """Not applicable — GuardDog dispatches a run per manifest/ecosystem.

        Like the ``container`` orchestrator, there is no single containerized
        invocation: ``scan`` walks the tree and runs ``guarddog <ecosystem>
        verify`` per manifest locally. Present (returning ``[]``) to satisfy
        the scanner container-args contract; there is no bundled image yet
        (``container_image`` is empty — see the module docstring).
        """
        return []

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _find_manifests(self, root: Path) -> list[Path]:
        """Locate supported manifests under ``root`` (skipping vendored dirs)."""
        if root.is_file():
            return [root] if root.name in _MANIFESTS else []
        found: list[Path] = []
        for candidate in sorted(root.rglob("*")):
            if candidate.name not in _MANIFESTS:
                continue
            if any(part in _SKIP_DIRS for part in candidate.parts):
                continue
            found.append(candidate)
        return found

    def _run_verify(self, ecosystem: str, manifest: Path, config: dict) -> list:
        """Run ``guarddog <ecosystem> verify <manifest> --output-format=json``."""
        cmd = ["guarddog", ecosystem, "verify", str(manifest), "--output-format=json"]
        for rule in config.get("rules") or []:
            cmd += ["--rules", str(rule)]
        for rule in config.get("exclude_rules") or []:
            cmd += ["--exclude-rules", str(rule)]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"guarddog timed out scanning {manifest}") from exc
        except FileNotFoundError as exc:
            raise RuntimeError("guarddog binary not found") from exc

        if not result.stdout.strip():
            raise RuntimeError(
                result.stderr.strip() or f"guarddog produced no output for {manifest}"
            )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"guarddog output JSON parse error for {manifest}: {exc}") from exc

    def parse_verify(self, data: list, ecosystem: str, manifest: Path) -> list[Finding]:
        """Convert GuardDog ``verify`` output (list of per-dependency dicts) to Findings.

        Each entry is ``{"dependency", "version", "result": {...}}`` where
        ``result.results`` maps a triggered rule name to its matches. One
        Finding per (dependency, triggered rule). The raw match ``code``
        excerpt is intentionally dropped — only rule/package/location surface.
        """
        findings: list[Finding] = []
        if not isinstance(data, list):
            return findings
        for entry in data:
            if not isinstance(entry, dict):
                continue
            dependency = entry.get("dependency", "")
            version = entry.get("version") or ""
            result = entry.get("result") or {}
            rule_results = result.get("results") or {}
            for rule, matches in rule_results.items():
                count = self._match_count(matches)
                if count == 0:
                    continue
                pkg_ref = f"{dependency}@{version}" if version else dependency
                findings.append(
                    Finding(
                        id=f"GUARDDOG-{rule}",
                        severity=Severity.HIGH,
                        title=f"Malicious-package indicator '{rule}' in {pkg_ref}",
                        description=(
                            f"GuardDog rule '{rule}' flagged {count} location(s) in "
                            f"{ecosystem} package '{pkg_ref}'. Review the package before "
                            f"trusting it. (Matched source excerpts are omitted here — "
                            f"re-run `guarddog {ecosystem} scan {dependency}` locally to inspect.)"
                        ),
                        location=pkg_ref,
                        scanner=self.name,
                        metadata={
                            "tool": "guarddog",
                            "ecosystem": ecosystem,
                            "package": dependency,
                            "installed_version": version,
                            "rule": rule,
                            "match_count": count,
                            "manifest": str(manifest),
                        },
                    )
                )
        return findings

    @staticmethod
    def _match_count(matches) -> int:
        """Number of hits for a rule's matches (list → len; truthy scalar → 1)."""
        if isinstance(matches, list):
            return len(matches)
        if isinstance(matches, dict):
            return len(matches)
        return 1 if matches else 0
