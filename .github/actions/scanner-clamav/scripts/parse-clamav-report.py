#!/usr/bin/env python3
"""Parse ClamAV scan report and generate JSON summary."""

import argparse
import json
import re
from pathlib import Path

parser = argparse.ArgumentParser(description='Parse ClamAV scan report and generate JSON summary')
parser.add_argument('--report-path', default='clamav-reports/clamav-report.log',
                    help='Path to ClamAV report file (default: clamav-reports/clamav-report.log)')
args = parser.parse_args()

report_file = Path(args.report_path)
if report_file.exists():
    content = report_file.read_text(encoding='utf-8')

    # Parse the summary line
    infected = 0
    scanned = 0

    if "Infected files:" in content:
        match = re.search(r'Infected files: (\d+)', content)
        if match:
            infected = int(match.group(1))

    if "Scanned files:" in content:
        match = re.search(r'Scanned files: (\d+)', content)
        if match:
            scanned = int(match.group(1))

    # Find infected file details
    infected_files = []
    for line in content.split('\n'):
        if 'FOUND' in line:
            infected_files.append(line.strip())

    results = []
    for line in infected_files:
        if ' FOUND ' in line:
            parts = line.split(' FOUND ', 1)
            if len(parts) == 2:
                results.append({
                    "file": parts[0].strip(),
                    "infection": parts[1].strip(),
                    "status": "infected"
                })

    json_data = {
        "total_files": scanned,
        "infected_files": infected,
        "clean_files": scanned - infected,
        "infections": infected_files,
        "results": results
    }

    # Write JSON to same directory as report file
    json_path = report_file.parent / f"{report_file.stem}.json"
    json_path.write_text(json.dumps(json_data, indent=2), encoding='utf-8')
    print(f"✅ Scan complete: {scanned} files scanned, {infected} infected")
else:
    print(f"⚠️  No scan report found at: {report_file}")
