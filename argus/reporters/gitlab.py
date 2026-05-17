"""GitLab Code Quality JSON reporter.

Emits a Code Climate-compatible JSON array that GitLab CI ingests
via the ``codequality`` report artifact. GitLab renders these in
the merge request widget with severity badges and (where the
``location.path`` is present in the diff) inline annotations.

Output file: ``gl-code-quality-report.json`` (default) — override
via reporter config ``output_filename``.

Severity mapping (Argus -> Code Climate):
    CRITICAL -> ``blocker``
    HIGH     -> ``critical``
    MEDIUM   -> ``major``
    LOW      -> ``minor``
    INFO     -> ``info``
    UNKNOWN  -> ``info``

Reference:
- GitLab Code Quality artifact:
  https://docs.gitlab.com/ee/ci/testing/code_quality.html
- Code Climate spec:
  https://github.com/codeclimate/platform/blob/master/spec/analyzers/SPEC.md
"""

import hashlib
import json
from pathlib import Path
from typing import Optional

from argus.core.models import Finding, ScanResult, ScanSummary, Severity


_SEVERITY_TO_GITLAB = {
    Severity.CRITICAL: "blocker",
    Severity.HIGH: "critical",
    Severity.MEDIUM: "major",
    Severity.LOW: "minor",
    Severity.INFO: "info",
    Severity.UNKNOWN: "info",
}

_DEFAULT_OUTPUT_DIR = Path("./argus-results")
_DEFAULT_FILENAME = "gl-code-quality-report.json"


class GitLabReporter:
    """Generate GitLab Code Quality JSON report."""

    def report(
        self,
        summary: ScanSummary,
        output_dir: Optional[Path] = None,
        config: Optional[dict] = None,
    ) -> Path:
        """Write the Code Climate-format report.

        Returns the path to the written file. ``config`` accepts
        ``output_filename`` to override the default
        ``gl-code-quality-report.json``.
        """
        dest = Path(output_dir) if output_dir else _DEFAULT_OUTPUT_DIR
        dest.mkdir(parents=True, exist_ok=True)

        filename = (config or {}).get("output_filename", _DEFAULT_FILENAME)
        filepath = dest / filename

        entries = [
            self._build_entry(result, finding)
            for result in summary.results
            for finding in result.findings
        ]

        filepath.write_text(
            json.dumps(entries, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return filepath

    def _build_entry(self, result: ScanResult, finding: Finding) -> dict:
        path, line = self._parse_location(finding.location)
        severity = _SEVERITY_TO_GITLAB.get(finding.severity, "info")

        # Linter findings (Severity.INFO) are style issues; everything
        # else is treated as security. This keeps the GitLab MR widget
        # filterable without needing to inspect the scanner name.
        category = "Style" if finding.severity == Severity.INFO else "Security"

        # GitLab Code Climate expects a single ``description`` string.
        # Concatenate title + description ONLY when they carry different
        # information — many linter rules (yamllint, flake8) ship the
        # same string for both, and the naive ``f"{title}: {description}"``
        # produced doubled output like ``"line too long ...: line too long ..."``
        # (issue #168-G).
        title = finding.title or ""
        desc = (finding.description or "").strip()
        if desc and desc != title and desc not in title and title not in desc:
            description = f"{title}: {desc}"
        else:
            description = desc or title

        return {
            "description": description,
            "severity": severity,
            "fingerprint": self._fingerprint(result.scanner, finding, path, line),
            "location": {
                "path": path or "",
                "lines": {"begin": line if line is not None else 0},
            },
            "check_name": f"{result.scanner}:{finding.id}",
            "categories": [category],
        }

    def _fingerprint(
        self,
        scanner: str,
        finding: Finding,
        path: Optional[str],
        line: Optional[int],
    ) -> str:
        """Stable 16-hex-char id for dedup across pipeline runs.

        GitLab uses ``fingerprint`` to track issue continuity across
        pipelines: same fingerprint = same issue. Hashing on
        ``(scanner, id, path, line)`` keeps the fingerprint stable
        across edits to the title/description of the underlying rule
        but bumps when the offending line moves.
        """
        material = "\x1f".join([
            scanner,
            finding.id,
            path or "",
            str(line) if line is not None else "",
        ])
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
        return digest[:16]

    def _parse_location(
        self, location: Optional[str]
    ) -> tuple[Optional[str], Optional[int]]:
        """Extract ``(path, line)`` from a ``path:line[:col]`` string."""
        if not location:
            return None, None

        parts = location.split(":")
        if len(parts) == 1:
            return parts[0] or None, None

        # Walk right-to-left collecting trailing integers. The first
        # non-numeric segment terminates the line/col tail; everything
        # before it is the path (rejoined with ``:`` so Windows drive
        # letters survive).
        line_no: Optional[int] = None
        cut = len(parts)
        for idx in range(len(parts) - 1, 0, -1):
            seg = parts[idx]
            if seg.isdigit():
                line_no = int(seg)  # line is the leftmost numeric
                cut = idx
            else:
                break

        path = ":".join(parts[:cut]) or None
        return path, line_no
