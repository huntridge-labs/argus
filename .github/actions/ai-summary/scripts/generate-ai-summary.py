#!/usr/bin/env python3
"""
generate-ai-summary.py
Reads aggregated scanner summaries and generates an executive summary.
Supports: GitHub Copilot | Anthropic Claude | Google Gemini
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path


# ───────────────────────────────── Config ─────────────────────────────────
SUMMARY_DIR  = os.environ.get("SUMMARY_DIR",  "/tmp/scanner-summaries")
OUTPUT_FILE  = os.environ.get("OUTPUT_FILE",  "/tmp/ai-summary.md")
MAX_FINDINGS = os.environ.get("MAX_FINDINGS", "20")
PROVIDER     = os.environ.get("AI_PROVIDER",  "copilot")
REPO         = os.environ.get("REPO",         "")
PR_NUMBER    = os.environ.get("PR_NUMBER",    "")
PR_TITLE     = os.environ.get("PR_TITLE",     "")
PR_URL       = os.environ.get("PR_URL",       "")
COMMIT_SHA   = os.environ.get("COMMIT_SHA",   "")

print(f"-> AI Provider: {PROVIDER}")


# ───────────────────────────────── Collect Scanner Summaries ─────────────────────────────────
print(f"-> Collecting scanner summaries from: {SUMMARY_DIR}")

summary_path = Path(SUMMARY_DIR)
if not summary_path.exists():
    print(f"ERROR: Summary directory not found: {SUMMARY_DIR}")
    sys.exit(1)

combined_findings = ""
scanner_count = 0
scanner_names = []

for summary_file in sorted(summary_path.glob("scanner-summary-*.md")):
    scanner_name = summary_file.stem.replace("scanner-summary-", "")
    print(f"  + Reading: {scanner_name}")
    combined_findings += f"### {scanner_name} findings\n"
    combined_findings += summary_file.read_text(encoding="utf-8")
    combined_findings += "\n\n"
    scanner_names.append(scanner_name.title())
    scanner_count += 1

if scanner_count == 0:
    print(f"ERROR: No scanner summary files found in {SUMMARY_DIR}")
    sys.exit(1)

print(f"-> Found summaries from {scanner_count} scanner(s)")

scanner_names_str = ", ".join(scanner_names)
date_str = datetime.now().strftime("%B %d, %Y")


# ───────────────────────────────── Build Prompt ─────────────────────────────────
PROMPT = f"""You are a security analyst writing an executive security summary from automated scan results.

Repository: {REPO}
Pull Request: {PR_TITLE} ({PR_URL})
Commit: {COMMIT_SHA}
Date: {date_str}
Scanners run: {scanner_count} ({scanner_names_str})

Raw scan findings (top {MAX_FINDINGS} findings per scanner):
{combined_findings}

Generate a professional executive security summary using the structure below. Only populate sections where relevant information exists in the scan findings. Do not invent or fabricate findings, CVEs, or recommendations not supported by the data. If a section or subsection has no relevant findings, omit it entirely.

---

## Key Findings Summary
Always include this section. A markdown table with columns: Risk Category | Count | Status. Only include rows where findings exist. Use these exact Risk Category names and status values:

| Risk Category | Count | Status |
|---|---|---|
| CRITICAL Vulnerabilities | [X unique CVEs (Y instances)] | ⚠️ IMMEDIATE ACTION REQUIRED |
| HIGH Vulnerabilities | [X unique CVEs (Y instances)] | ⚠️ ACTION REQUIRED |
| MEDIUM/LOW Vulnerabilities | [X unique CVEs (Y instances)] | 🔧 REMEDIATION RECOMMENDED |
| Exposed Secrets | [X instances] | ⚠️ IMMEDIATE ACTION REQUIRED |
| Infrastructure Misconfigurations | [X findings] | 🔧 REMEDIATION RECOMMENDED |

Only include rows where findings exist. For vulnerability counts, always specify both unique CVEs and total instances where available (e.g. "6 unique CVEs (30 instances)"). For secrets and misconfigurations use instance/findings count only.

---

## Executive Overview
1-2 sentences summarizing the overall security posture based on the findings. Mention the tools used and the general risk level.

---

## Critical Risk Areas

### 1. Critical Priority Vulnerabilities
Only include if CRITICAL severity findings exist. Structure each finding group using these bolded subsections:
- **Overview:** What the vulnerability is in 1-2 sentences
- **Breakdown:** List each CVE or finding with a brief description
- **Impact:** Bullet points of what an attacker could do if exploited
- **Affected Components:** What is affected (files, images, packages)
- **Recommendation:** One clear remediation action

### 2. High-Severity Vulnerabilities
Only include if HIGH severity findings exist. Use the same bolded subsection structure:
- **Overview:** What the vulnerabilities are in 1-2 sentences
- **Breakdown:** List notable CVEs with brief descriptions
- **Impact:** Bullet points of potential attacker actions
- **Affected Components:** What is affected
- **Recommendation:** One clear remediation action

### 3. Infrastructure & Configuration Issues
Only include if infrastructure misconfigurations or IaC findings exist. Use the same bolded subsection structure:
- **Overview:** Summary of misconfiguration types found
- **Breakdown:** List each issue with a brief description
- **Impact:** Bullet points of potential consequences
- **Affected Components:** What is affected
- **Recommendation:** One clear remediation action

---

## Risk Assessment
State the overall risk level (CRITICAL / HIGH / MEDIUM / LOW) followed by 3-4 bullet points explaining the rationale based on the actual findings.

---

## Recommended Actions
Number all actions sequentially across ALL time buckets (1, 2, 3... continuing through each section without resetting). Bold each action. Use the exact icons shown for each label.

### Immediate (Within 24-48 Hours)
Actions for CRITICAL findings only. Use ✅ icon:
1. ✅ **[Action]**

### Short-Term (Within 1-2 Weeks)
Actions for HIGH severity findings. Use ⚙️ icon, continuing the numbering:
[n]. ⚙️ **[Action]**

### Medium-Term (Within 30 Days)
Actions for MEDIUM severity findings. Use 📋 icon, continuing the numbering:
[n]. 📋 **[Action]**

### Ongoing
Recurring security hygiene. Use 🔄 icon, continuing the numbering:
[n]. 🔄 **[Action]**

---

## Compliance Considerations
Identify 2-4 compliance frameworks likely impacted by these specific findings (e.g. NIST 800-53, FedRAMP, HIPAA, SOC 2, PCI-DSS). One line per framework explaining why it is relevant. Only include frameworks genuinely applicable to the findings.

---

## Appendices

### A. Scanning Tools Used
List only the scanners that actually ran and produced findings, with a one-line description of what each tool does.

### B. Affected Containers
List any container images identified in the findings. Omit if no container findings exist.

### C. Additional Resources
Omit this section entirely - leave blank rather than filling with placeholder text.

---

## Contact Information
Leave this section with the placeholder: '[Insert security team contact information]'

---

Rules:
- Only populate sections where the scan data supports it - omit empty sections entirely
- Use actual CVE IDs, file paths, and line numbers from the findings where available
- Keep language professional but accessible to a technical lead reviewing a PR
- Do not add any preamble or closing remarks outside the defined sections
- Do not invent content for the Appendices or Contact Information sections
"""


# ───────────────────────────────── Run AI Provider ─────────────────────────────────
print(f"-> Generating AI summary via {PROVIDER}...")

summary_output = ""

if PROVIDER == "copilot":
    try:
        result = subprocess.run(
            ["copilot", "-p", PROMPT],
            capture_output=True,
            text=True,
        )
        raw_lines = result.stdout.splitlines()
        filtered = [
            line for line in raw_lines
            if not any([
                line.startswith("!"),
                line.startswith("Total usage"),
                line.startswith("API time"),
                line.startswith("Total session"),
                line.startswith("Breakdown"),
                "gpt-" in line,
                line.startswith("claude-"),
            ])
        ]
        summary_output = "\n".join(filtered)
    except FileNotFoundError:
        print("ERROR: copilot CLI not found. Is @github/copilot installed?")
        sys.exit(1)

elif PROVIDER == "claude":
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set")
        sys.exit(1)

    body = json.dumps({
        "model":      "claude-sonnet-4-5",
        "max_tokens": 2048,
        "system":     "You are a security analyst writing executive summaries from automated scan results.",
        "messages":   [{"role": "user", "content": PROMPT}],
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "x-api-key":         api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type":      "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        print("DEBUG: Claude response received")
        summary_output = data["content"][0]["text"].strip()
    except urllib.error.HTTPError as e:
        print(f"ERROR: Claude API call failed - {e.code} {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Claude API call failed - {e}")
        sys.exit(1)

elif PROVIDER == "gemini":
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("ERROR: GEMINI_API_KEY not set")
        sys.exit(1)

    body = json.dumps({
        "contents":         [{"parts": [{"text": PROMPT}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 2048},
    }).encode("utf-8")

    req = urllib.request.Request(
        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        print("DEBUG: Gemini response received")
        summary_output = data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except urllib.error.HTTPError as e:
        print(f"ERROR: Gemini API call failed - {e.code} {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Gemini API call failed - {e}")
        sys.exit(1)

else:
    print(f"ERROR: Unknown provider '{PROVIDER}'. Valid options: copilot, claude, gemini")
    sys.exit(1)


# ───────────────────────────────── Validate Output ─────────────────────────────────
if not summary_output or not summary_output.strip():
    print(f"ERROR: {PROVIDER} returned empty response")
    sys.exit(1)


# ───────────────────────────────── Write Output ─────────────────────────────────
provider_labels = {
    "copilot": "GitHub Copilot",
    "claude":  "Anthropic Claude",
    "gemini":  "Google Gemini",
}
provider_label = provider_labels.get(PROVIDER, PROVIDER)

short_sha = COMMIT_SHA[:7] if len(COMMIT_SHA) >= 7 else COMMIT_SHA

final_output = f"""## Security Scan Executive Summary

> Generated by Argus AI Summary | Powered by {provider_label}
> Repository: {REPO} | PR: [#{PR_NUMBER}]({PR_URL}) | Commit: `{short_sha}` | Date: {date_str}

{summary_output}

---
*Scan covered {scanner_count} security tool(s): {scanner_names_str}. This summary is AI-generated - review findings directly before merge decisions.*
"""

Path(OUTPUT_FILE).write_text(final_output, encoding="utf-8")

print(f"-> Summary written to: {OUTPUT_FILE}")
print("✅ AI summary generation complete")