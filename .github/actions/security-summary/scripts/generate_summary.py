"""Generate the security-summary combined report.

Called from the security-summary composite action. All configuration flows in
via environment variables populated by the action's `env:` block; the single
positional argument controls which output destination to write to.

Responsibilities:

1. Optionally render a per-scanner status table at the top of the report,
   driven by ``SCAN_STATUSES_JSON``. When scan_statuses is supplied, the
   table is the source of truth — the aggregator will call out any scanner
   whose job did not succeed, and the caller can choose to exit non-zero
   to block downstream consumers.
2. Discover scanner summary markdown files under ``scanner-summaries/``
   and stitch them into the output, stripping a redundant outer
   ``<details>/<summary>`` wrapper so reviewers don't have to click twice
   to see each scanner's findings.
3. Emit ``overall_status`` / ``failed_count`` to ``$GITHUB_OUTPUT`` so the
   composite can fail the job when any scanner did not succeed.

The script is intentionally dependency-free (stdlib only) so it can run on
any composite consumer without a separate ``pip install`` step.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable


STATUS_BADGES = {
    "success": "✅ PASS",
    "failure": "❌ FAIL",
    "cancelled": "⏹️ cancelled",
    "skipped": "⏭️ skipped",
    "not-run": "◻️ not run",
}

# A scanner is considered "failed" (blocking) when its result is neither a
# clean success nor an intentional non-run (skipped because not selected, or
# left blank because the caller didn't wire it up). Cancelled counts as
# failure because it means we can't trust the findings.
PASSING_STATES = frozenset({"success", "skipped", "not-run"})


def parse_scan_statuses(raw: str) -> dict[str, str]:
    """Parse the SCAN_STATUSES_JSON env input into a normalized dict.

    Returns an empty dict when the input is blank. Emits a GitHub Actions
    warning and returns an empty dict when the input is not valid JSON,
    rather than crashing the whole report.
    """
    raw = (raw or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(
            f"::warning title=security-summary::scan_statuses is not valid JSON ({exc}); "
            "falling back to discovery-only mode",
            file=sys.stderr,
            flush=True,
        )
        return {}
    if not isinstance(parsed, dict):
        print(
            "::warning title=security-summary::scan_statuses must be a JSON object; "
            "falling back to discovery-only mode",
            file=sys.stderr,
            flush=True,
        )
        return {}
    # Normalize empty strings to "not-run" so callers can safely wire
    # `needs.*.result` for jobs that may never have started.
    return {str(k): (str(v).strip() or "not-run") for k, v in parsed.items()}


def render_status_table(statuses: dict[str, str]) -> list[str]:
    """Return the markdown lines for the per-scanner status table.

    Returns an empty list when ``statuses`` is empty so callers can skip the
    whole block rather than emit an empty table.
    """
    if not statuses:
        return []
    lines: list[str] = ["### Scan Status", "", "| Scanner | Status |", "|---------|--------|"]
    for name in sorted(statuses):
        badge = STATUS_BADGES.get(statuses[name], f"❓ {statuses[name]}")
        lines.append(f"| `{name}` | {badge} |")
    lines.append("")
    failed = sorted(n for n, r in statuses.items() if r not in PASSING_STATES)
    if failed:
        lines.append(
            f"> **❌ {len(failed)} scanner(s) failed:** "
            + ", ".join(f"`{n}`" for n in failed)
            + "."
        )
        lines.append(
            "> Downstream consumers should treat this report as blocking — the scan "
            "findings below are not complete."
        )
    else:
        lines.append("> **✅ All enabled scanners completed successfully.**")
    lines.append("")
    return lines


_OUTER_DETAILS_RE = re.compile(
    r"\A<details[^>]*>\s*<summary[^>]*>(?P<title>.*?)</summary>(?P<body>.*)</details>\s*\Z",
    re.DOTALL | re.IGNORECASE,
)


def normalize_summary(md_text: str) -> str:
    """Strip a single layer of outer <details>/<summary> wrapping.

    Many Argus-SDK-native summaries ship pre-wrapped in a `<details>` block so
    they collapse nicely when embedded in a PR comment. When we then wrap the
    whole set in *another* `<details>`, reviewers have to click twice to see
    anything — the UX bug that bit the medsecops-golden-path demo in the
    initial rollout. This function converts a single outer wrapper into a
    plain markdown heading so the section title is visible without a click.

    If the document is NOT a single outer-wrapped block (e.g., it already
    starts with plain markdown, or contains multiple top-level elements), it
    is returned unchanged so we don't mangle arbitrary author markup.
    """
    stripped = md_text.strip()
    match = _OUTER_DETAILS_RE.match(stripped)
    if not match:
        return md_text if md_text.endswith("\n") else md_text + "\n"
    title = re.sub(r"<[^>]+>", "", match.group("title")).strip()
    body = match.group("body").strip()
    parts: list[str] = []
    if title:
        parts.append(f"#### {title}")
        parts.append("")
    parts.append(body)
    parts.append("")
    return "\n".join(parts)


def gather_summary_files(summaries_dir: Path) -> list[Path]:
    """Return sorted markdown files in the summaries dir (empty list if absent)."""
    if not summaries_dir.is_dir():
        return []
    return sorted(p for p in summaries_dir.glob("*.md") if p.is_file())


def render_scanner_results(
    summary_files: Iterable[Path],
    show_stats: bool,
) -> list[str]:
    """Return the markdown lines for the "Scanner Results" section."""
    files = list(summary_files)
    lines: list[str] = []
    if files:
        if show_stats:
            lines.append(f"**Summaries Collected:** {len(files)}")
            lines.append("")
        lines.append("### Scanner Results")
        lines.append("")
        for md_file in files:
            lines.append(normalize_summary(md_file.read_text(encoding="utf-8")))
    else:
        lines.append("### Scanner Results")
        lines.append("")
        lines.append("_No scanner summary artifacts were uploaded._")
        lines.append("")
        lines.append(
            "The status table above is the source of truth for which scanners ran. "
            "An empty summary set with some scanners marked ❌/⏹️ typically means the scan "
            "job failed before producing output — inspect the scanner job logs for the "
            "root cause."
        )
    return lines


def build_report(
    *,
    title: str,
    show_metadata: bool,
    show_stats: bool,
    include_title: bool,
    statuses: dict[str, str],
    summary_files: list[Path],
    metadata: dict[str, str],
) -> str:
    """Assemble the full markdown report as a single string."""
    lines: list[str] = []
    if include_title and title:
        lines.append(title)
        lines.append("")

    if show_metadata:
        run_number = metadata.get("run_number", "")
        server_url = metadata.get("server_url", "")
        repository = metadata.get("repository", "")
        run_id = metadata.get("run_id", "")
        branch = metadata.get("head_ref") or metadata.get("ref_name", "")
        commit = metadata.get("commit_sha", "")
        short_commit = commit[:7] if commit else ""
        lines.append(
            f"**Workflow Run:** [{run_number}]({server_url}/{repository}/actions/runs/{run_id})"
        )
        lines.append(f"**Branch:** `{branch}`")
        lines.append(f"**Commit:** [`{short_commit}`]({server_url}/{repository}/commit/{commit})")
        lines.append("")

    lines.extend(render_status_table(statuses))
    lines.extend(render_scanner_results(summary_files, show_stats=show_stats))

    lines.append("")
    lines.append("---")
    lines.append("_Generated by [Argus](https://github.com/huntridge-labs/argus)_")
    return "\n".join(lines) + "\n"


def _write_github_output(overall: str, failed_count: int) -> None:
    """Append outputs to $GITHUB_OUTPUT when that env var is set."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as fh:
        fh.write(f"overall_status={overall}\n")
        fh.write(f"failed_count={failed_count}\n")


def derive_overall_status(statuses: dict[str, str]) -> tuple[str, int]:
    """Compute the overall verdict and count of failing scanners."""
    if not statuses:
        return "unknown", 0
    failed = [n for n, r in statuses.items() if r not in PASSING_STATES]
    return ("failure" if failed else "success", len(failed))


def main(argv: list[str]) -> int:
    """Script entry point — see module docstring for the full contract."""
    if len(argv) < 3:
        print(
            "usage: generate_summary.py <output_path> <include_title:true|false>",
            file=sys.stderr,
        )
        return 2

    output_path = Path(argv[1])
    include_title = argv[2].lower() == "true"

    statuses = parse_scan_statuses(os.environ.get("SCAN_STATUSES_JSON", ""))
    summary_files = gather_summary_files(Path("scanner-summaries"))

    report = build_report(
        title=os.environ.get("SUMMARY_TITLE", "🔒 Security Scan Summary"),
        show_metadata=os.environ.get("SHOW_METADATA", "true").lower() == "true",
        show_stats=os.environ.get("SHOW_STATS", "true").lower() == "true",
        include_title=include_title,
        statuses=statuses,
        summary_files=summary_files,
        metadata={
            "run_number": os.environ.get("RUN_NUMBER", ""),
            "server_url": os.environ.get("SERVER_URL", ""),
            "repository": os.environ.get("REPOSITORY", ""),
            "run_id": os.environ.get("RUN_ID", ""),
            "head_ref": os.environ.get("HEAD_REF", ""),
            "ref_name": os.environ.get("REF_NAME", ""),
            "commit_sha": os.environ.get("COMMIT_SHA", ""),
        },
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")

    overall, failed_count = derive_overall_status(statuses)
    _write_github_output(overall, failed_count)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
