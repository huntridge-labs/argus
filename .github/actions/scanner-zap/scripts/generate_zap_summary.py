#!/usr/bin/env python3
"""Generate ZAP DAST summary from scan results.

Environment variables:
  ZAP_PARSER         - Path to ZAP parser script (required)
  ZAP_SCAN_TYPE      - Scan type for title (baseline/full/api, optional)
  GITHUB_STEP_SUMMARY - Path to step summary file (optional)
  GITHUB_REPOSITORY   - Repository name for links (optional)
  GITHUB_RUN_ID       - Run ID for artifact links (optional)
  GITHUB_SERVER_URL   - GitHub server URL (optional)
"""

import os
import subprocess
import json
from pathlib import Path


def get_env(key, default=''):
    """Get environment variable with default."""
    return os.environ.get(key, default)


def ensure_parser():
    """Ensure ZAP_PARSER environment variable is set."""
    parser = get_env('ZAP_PARSER')
    if not parser:
        raise RuntimeError("ZAP_PARSER must be set")
    return parser


def format_scan_type(scan_type='', scan_mode=''):
    """Format scan type for display."""
    display = ''
    if scan_type:
        type_map = {
            'baseline': ' - Baseline',
            'full': ' - Full Scan',
            'api': ' - API Scan',
        }
        display = type_map.get(scan_type.lower(), f' - {scan_type.title()}')

    mode_display = ''
    if scan_mode:
        mode_display = f' ({scan_mode})'

    return display + mode_display


def run_parser(parser_path, command, report_path, severity=None, limit=50):
    """Run the parser script and return output."""
    cmd = [parser_path, command, report_path]
    if severity:
        cmd.extend(['-s', severity])
    if limit != 50:
        cmd.extend(['-l', str(limit)])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout.strip()
    except Exception as e:
        print(f"Error running parser: {e}")
        return ""


def get_counts(parser_path, report_path):
    """Get alert counts from parser."""
    output = run_parser(parser_path, 'counts', report_path)
    if not output:
        return 0, 0, 0, 0
    parts = output.split()
    try:
        return int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
    except (ValueError, IndexError):
        return 0, 0, 0, 0


def get_counts_with_info(parser_path, report_path):
    """Get alert counts including informational."""
    output = run_parser(parser_path, 'counts-with-info', report_path)
    if not output:
        return 0, 0, 0, 0, 0
    parts = output.split()
    try:
        return int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]), int(parts[4])
    except (ValueError, IndexError):
        return 0, 0, 0, 0, 0


def get_total(parser_path, report_path):
    """Get total alert count."""
    output = run_parser(parser_path, 'total', report_path)
    try:
        return int(output)
    except (ValueError, TypeError):
        return 0


def get_unique(parser_path, report_path):
    """Get unique alert count."""
    output = run_parser(parser_path, 'unique', report_path)
    try:
        return int(output)
    except (ValueError, TypeError):
        return 0


def get_target(parser_path, report_path):
    """Get target URL from report."""
    output = run_parser(parser_path, 'target', report_path)
    return output if output else 'unknown'


def find_reports():
    """Find all ZAP report files."""
    reports = []
    zap_downloads = Path('zap-downloads')

    if not zap_downloads.exists():
        return reports

    # Find all report_json.json files
    for report_path in zap_downloads.rglob('report_json.json'):
        if report_path.is_file():
            reports.append(report_path)

    return sorted(reports)


def extract_scan_type_from_artifact(artifact_name):
    """Extract scan type from artifact name."""
    # Format: zap-reports-{inv_key}-{inv_nonce}-{scan_type}-{job_id}
    # or: zap-reports-{scan_type}-{hash}
    if 'zap-reports-' not in artifact_name:
        return 'unknown'

    remainder = artifact_name.replace('zap-reports-', '')

    # Look for baseline, full, or api in the name
    for scan_type in ['baseline', 'full', 'api']:
        if f'-{scan_type}-' in remainder or remainder.startswith(f'{scan_type}-'):
            return scan_type

    return 'unknown'


def write_summary_header(output_file, scan_type_display):
    """Write summary header to output file."""
    if output_file.name == 'zap.md':
        output_file.write_text(
            f'<details><summary>🕷️ ZAP (DAST){scan_type_display}</summary>\n'
            f'\n**Status:** ✅ Completed\n',
            encoding='utf-8'
        )
    else:
        output_file.write_text(
            f'## 🕷️ ZAP DAST Summary{scan_type_display}\n\n',
            encoding='utf-8'
        )


def write_skipped_summary(scan_type_display):
    """Write skipped summary to output files."""
    summary_dir = Path('scanner-summaries')
    summary_dir.mkdir(parents=True, exist_ok=True)

    summary_file = summary_dir / 'zap.md'
    summary_file.write_text(
        f'<details><summary>🕷️ ZAP (DAST){scan_type_display}</summary>\n'
        f'\n**Status:** ⏭️ Skipped\n\n</details>\n',
        encoding='utf-8'
    )

    step_summary = get_env('GITHUB_STEP_SUMMARY')
    if step_summary:
        with open(step_summary, 'a', encoding='utf-8') as f:
            f.write(f'## 🕷️ ZAP DAST Summary{scan_type_display}\n\n')
            f.write('**Status:** ⏭️ No scans performed\n')


def append_to_file(file_path, content):
    """Append content to file."""
    with open(file_path, 'a', encoding='utf-8') as f:
        f.write(content)


def run_details_command(parser_path, report_path, severity, limit):
    """Run parser details command and return output."""
    return run_parser(parser_path, 'details', report_path, severity=severity, limit=limit)


def run_compact_table_command(parser_path, report_path, severity, limit):
    """Run parser compact-table command and return output."""
    return run_parser(parser_path, 'compact-table', report_path, severity=severity, limit=limit)


def main():
    """Main entry point."""
    print("📊 Generating ZAP DAST summary...")

    # Ensure required env vars
    parser_path = ensure_parser()

    # Debug output
    print("🔍 Looking for ZAP artifacts in: zap-downloads/")
    print(f"🔍 Current directory: {os.getcwd()}")

    zap_downloads = Path('zap-downloads')
    if zap_downloads.exists():
        print(f"🔍 Zap downloads directory structure:")
        for item in zap_downloads.iterdir():
            print(f"  {item.name}")
    else:
        print("  ⚠️  zap-downloads/ directory not found")

    # Find reports
    reports = find_reports()
    print(f"🔍 Found {len(reports)} report file(s)")
    for report in reports:
        print(f"  ✅ Found report: {report}")

    # Initialize aggregates
    total_crit = 0
    total_high = 0
    total_med = 0
    total_low = 0
    scanned = 0
    failed = 0
    scan_results = []

    # Process each report
    for report_path in reports:
        report_path = report_path.resolve()
        print(f"  ✅ Processing: {report_path}")

        # Determine artifact name and scan type
        parent_dir = report_path.parent
        if parent_dir.name == 'zap-downloads':
            artifact_name = 'zap-reports-single-artifact'
            scan_type = get_env('ZAP_SCAN_TYPE', 'unknown')
            print(f"  📦 Single artifact detected, using scan_type from env: {scan_type}")
        else:
            artifact_name = parent_dir.name
            scan_type = extract_scan_type_from_artifact(artifact_name)
            print(f"  📦 Artifact name: {artifact_name}")
            print(f"  ✅ Extracted scan_type: {scan_type}")

        # Get counts from parser
        crit, high, med, low = get_counts(parser_path, str(report_path))
        total = crit + high + med + low
        unique = get_unique(parser_path, str(report_path))
        target = get_target(parser_path, str(report_path))

        # Store results
        scan_results.append({
            'scan_type': scan_type,
            'target': target,
            'crit': crit,
            'high': high,
            'med': med,
            'low': low,
            'total': total,
            'unique': unique,
            'artifact_name': artifact_name,
        })

        total_crit += crit
        total_high += high
        total_med += med
        total_low += low
        scanned += 1

        print(f"  ✅ {scan_type} scan on {target}: {total} alerts "
              f"({crit} crit, {high} high, {med} med, {low} low)")

    # Check if we have results
    if scanned == 0:
        print("⏭️ No ZAP scan results found")
        write_skipped_summary(format_scan_type())
        return

    total = total_crit + total_high + total_med + total_low

    # Determine scan type display
    if scanned == 1:
        scan_type_display = format_scan_type(scan_results[0]['scan_type'], get_env('ZAP_SCAN_MODE'))
    else:
        scan_type_display = ''

    # Create output directory
    summary_dir = Path('scanner-summaries')
    summary_dir.mkdir(parents=True, exist_ok=True)

    # Build output targets
    output_targets = [summary_dir / 'zap.md']
    step_summary_path = get_env('GITHUB_STEP_SUMMARY')
    if step_summary_path:
        output_targets.append(Path(step_summary_path))

    # Generate reports for each output target
    for output_path in output_targets:
        output_path = output_path.resolve()

        # Write header
        write_summary_header(output_path, scan_type_display)

        # Summary table
        summary_table = f"""### 📊 Overall Findings Summary

| 🚨 Critical | ⚠️ High | 🟡 Medium | 🔵 Low | 📦 Total |
|-------------|---------|-----------|---------|----------|
| **{total_crit}** | **{total_high}** | **{total_med}** | **{total_low}** | **{total}** |

**Scanned:** {scanned} target(s) | **Scan Failures:** {failed}

"""
        append_to_file(output_path, summary_table)

        # Scan breakdown (only for multiple scans)
        if scanned > 1:
            breakdown = "### 📦 Scan Breakdown\n\n"
            breakdown += "| Scan Type | Target | 🚨 Crit | ⚠️ High | 🟡 Med | 🔵 Low | Total | Unique | Status |\n"
            breakdown += "|-----------|--------|---------|---------|--------|--------|-------|--------|--------|\n"
            for result in scan_results:
                breakdown += (f"| {result['scan_type']} | `{result['target']}` | "
                            f"{result['crit']} | {result['high']} | {result['med']} | {result['low']} | "
                            f"{result['total']} | {result['unique']} | ✅ |\n")
            breakdown += "\n"
            append_to_file(output_path, breakdown)

        # Detailed findings
        findings = "### 🔍 Detailed Findings by Scan\n\n"
        append_to_file(output_path, findings)

        for result in scan_results:
            # Determine emoji
            if result['crit'] > 0:
                emoji = '🚨'
            elif result['high'] > 0:
                emoji = '⚠️'
            elif result['total'] > 0:
                emoji = '🟡'
            else:
                emoji = '✅'

            # Build artifact path
            if result['artifact_name'] == 'zap-reports-single-artifact':
                report_file = './zap-downloads/report_json.json'
            else:
                report_file = f"./zap-downloads/{result['artifact_name']}/report_json.json"

            section = f"""<details>
<summary>{emoji} <strong>{result['scan_type']} scan</strong> on <code>{result['target']}</code> - {result['total']} alerts ({result['unique']} unique)</summary>

**Target:** `{result['target']}`
**Scan Type:** {result['scan_type']}

#### Alert Summary

| 🚨 Critical | ⚠️ High | 🟡 Medium | 🔵 Low | Total | Unique |
|-------------|---------|-----------|---------|-------|--------|
| {result['crit']} | {result['high']} | {result['med']} | {result['low']} | {result['total']} | {result['unique']} |

"""
            append_to_file(output_path, section)

            # Add detailed findings if report exists
            if Path(report_file).exists():
                if result['total'] == 0:
                    append_to_file(output_path, "✅ No security alerts detected\n")
                else:
                    # Critical findings
                    if result['crit'] > 0:
                        details = run_details_command(parser_path, report_file, 'critical', 50)
                        if details:
                            append_to_file(output_path,
                                         f"<details>\n<summary>🚨 <strong>Critical Severity</strong> ({result['crit']} findings)</summary>\n\n"
                                         f"{details}\n</details>\n\n")

                    # High findings
                    if result['high'] > 0:
                        details = run_details_command(parser_path, report_file, 'high', 50)
                        if details:
                            append_to_file(output_path,
                                         f"<details>\n<summary>⚠️ <strong>High Severity</strong> ({result['high']} findings)</summary>\n\n"
                                         f"{details}\n</details>\n\n")

                    # Medium findings (compact table)
                    if result['med'] > 0:
                        table = run_compact_table_command(parser_path, report_file, 'medium', 50)
                        if table:
                            append_to_file(output_path,
                                         f"<details>\n<summary>🟡 <strong>Medium Severity</strong> ({result['med']} findings)</summary>\n\n"
                                         f"{table}\n\n</details>\n\n")

                    # Low findings (compact table)
                    if result['low'] > 0:
                        table = run_compact_table_command(parser_path, report_file, 'low', 50)
                        if table:
                            append_to_file(output_path,
                                         f"<details>\n<summary>🔵 <strong>Low Severity</strong> ({result['low']} findings)</summary>\n\n"
                                         f"{table}\n\n</details>\n\n")

            append_to_file(output_path, "\n</details>\n\n")

        # Artifact link
        repo = get_env('GITHUB_REPOSITORY')
        run_id = get_env('GITHUB_RUN_ID')
        server_url = get_env('GITHUB_SERVER_URL', 'https://github.com')

        if repo and run_id:
            artifact_link = (f"**📁 Artifacts:** [{server_url}/{repo}/actions/runs/{run_id}#artifacts]"
                           f"({server_url}/{repo}/actions/runs/{run_id}#artifacts)\n")
            append_to_file(output_path, artifact_link)

        # Close details tag for zap.md
        if output_path.name == 'zap.md':
            append_to_file(output_path, "\n</details>\n")

    print("✅ ZAP summary generated")


if __name__ == '__main__':
    main()
