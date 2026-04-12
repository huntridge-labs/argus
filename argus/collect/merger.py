"""Merge per-scanner audit artifacts into combined outputs.

Handles JSONL log merging (sorted by timestamp), audit manifest
combination, and markdown summary aggregation.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("argus.collect")


def merge_logs(log_files: list[Path], output: Path) -> int:
    """Merge multiple JSONL log files into one, sorted by timestamp.

    Returns the number of log entries written.
    """
    entries: list[tuple[str, str]] = []  # (timestamp, raw_line)

    for log_file in log_files:
        if not log_file.exists():
            logger.debug("Log file not found, skipping: %s", log_file)
            continue

        scanner_name = _infer_scanner_name(log_file)
        for line in log_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                # Tag with scanner source if not already present
                if "scanner" not in entry:
                    entry["scanner"] = scanner_name
                ts = entry.get("timestamp", "")
                entries.append((ts, json.dumps(entry)))
            except json.JSONDecodeError:
                # Non-JSON line — keep it with a synthetic timestamp
                entries.append(("9999", line))

    # Sort by timestamp (ISO 8601 sorts lexicographically)
    entries.sort(key=lambda e: e[0])

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "\n".join(line for _, line in entries) + "\n",
        encoding="utf-8",
    )

    logger.info(
        "Merged %d log entries from %d file(s) → %s",
        len(entries),
        len(log_files),
        output,
    )
    return len(entries)


def merge_manifests(manifest_files: list[Path], output: Path) -> dict:
    """Merge per-scanner audit manifests into a combined manifest.

    Combines timing (earliest start, latest end), aggregates findings,
    collects all scanner metadata, and inventories all artifacts.
    """
    manifests = []
    for mf in manifest_files:
        if not mf.exists():
            continue
        try:
            manifests.append(json.loads(mf.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to read manifest %s: %s", mf, exc)

    if not manifests:
        logger.warning("No manifests to merge")
        return {}

    combined = _build_combined_manifest(manifests)

    # Inventory all files in the output directory (will be filled after copy)
    # Caller should call _inventory_artifacts after populating the output dir

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(combined, indent=2, default=str),
        encoding="utf-8",
    )

    logger.info(
        "Merged %d manifest(s) → %s (%d scanner(s), %d total findings)",
        len(manifests),
        output,
        len(combined.get("scanners_executed", [])),
        combined.get("findings_summary", {}).get("total", 0),
    )
    return combined


def inventory_artifacts(output_dir: Path, manifest_path: Path) -> None:
    """Update a combined manifest with SHA-256 hashes of all artifacts.

    Call this after all files have been copied to output_dir.
    """
    if not manifest_path.exists():
        return

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifacts = []
    for f in sorted(output_dir.rglob("*")):
        if not f.is_file():
            continue
        rel = str(f.relative_to(output_dir))
        artifacts.append({
            "path": rel,
            "size_bytes": f.stat().st_size,
            "sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
        })

    manifest["artifacts"] = artifacts
    manifest_path.write_text(
        json.dumps(manifest, indent=2, default=str),
        encoding="utf-8",
    )
    logger.debug("Inventoried %d artifacts in %s", len(artifacts), output_dir)


def merge_summaries(summary_files: list[Path], output: Path) -> None:
    """Concatenate per-scanner markdown summaries into one file."""
    parts: list[str] = []
    for sf in sorted(summary_files):
        if sf.exists():
            content = sf.read_text(encoding="utf-8").strip()
            if content:
                parts.append(content)

    if not parts:
        output.write_text("No scanner summaries available.\n", encoding="utf-8")
        return

    combined = "\n\n---\n\n".join(parts)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(combined + "\n", encoding="utf-8")
    logger.info("Merged %d summary file(s) → %s", len(parts), output)


def _build_combined_manifest(manifests: list[dict]) -> dict:
    """Build a combined manifest from individual scanner manifests."""
    # Use the first manifest as a template for shared fields
    base = manifests[0].copy()

    # Timing: earliest start, latest end
    starts = [m["started_at"] for m in manifests if m.get("started_at")]
    ends = [m["completed_at"] for m in manifests if m.get("completed_at")]

    combined = {
        "argus_version": base.get("argus_version", ""),
        "scan_id": f"combined-{base.get('scan_id', 'unknown')[:8]}",
        "started_at": min(starts) if starts else "",
        "completed_at": max(ends) if ends else "",
        "duration_ms": 0,
        "platform": base.get("platform", {}),
        "hostname": base.get("hostname", ""),
        "python_version": base.get("python_version", ""),
        "os_info": base.get("os_info", ""),
        "scan_targets": [],
        "config_file": base.get("config_file", ""),
        "config_hash": base.get("config_hash", ""),
        "scanners_executed": [],
        "tool_versions": {},
        "container_images": {},
        "execution_backend": base.get("execution_backend", ""),
        "findings_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        "exit_code": 0,
        "phases": [],
        "artifacts": [],
        "scanner_manifests": [],  # Individual manifests for reference
    }

    # Calculate duration
    if combined["started_at"] and combined["completed_at"]:
        try:
            start = datetime.fromisoformat(combined["started_at"])
            end = datetime.fromisoformat(combined["completed_at"])
            combined["duration_ms"] = int((end - start).total_seconds() * 1000)
        except (ValueError, TypeError):
            pass

    # Aggregate across all manifests
    all_targets: set[str] = set()
    for m in manifests:
        # Scanners
        combined["scanners_executed"].extend(m.get("scanners_executed", []))

        # Targets
        all_targets.update(m.get("scan_targets", []))

        # Findings
        for sev in ("critical", "high", "medium", "low", "total"):
            combined["findings_summary"][sev] += m.get("findings_summary", {}).get(sev, 0)

        # Container images
        combined["container_images"].update(m.get("container_images", {}))

        # Tool versions
        combined["tool_versions"].update(m.get("tool_versions", {}))

        # Exit code: worst wins
        combined["exit_code"] = max(combined["exit_code"], m.get("exit_code", 0))

        # Phases
        combined["phases"].extend(m.get("phases", []))

        # Keep individual manifest reference
        combined["scanner_manifests"].append({
            "scan_id": m.get("scan_id", ""),
            "scanners": m.get("scanners_executed", []),
            "duration_ms": m.get("duration_ms", 0),
            "findings_total": m.get("findings_summary", {}).get("total", 0),
        })

    combined["scan_targets"] = sorted(all_targets)

    return combined


def _infer_scanner_name(log_file: Path) -> str:
    """Infer scanner name from the directory structure.

    Expects: collected/argus-results-bandit/argus.log → "bandit"
    """
    parent = log_file.parent.name
    if parent.startswith("argus-results-"):
        return parent.replace("argus-results-", "")
    return parent
