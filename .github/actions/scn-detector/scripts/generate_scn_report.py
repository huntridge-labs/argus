#!/usr/bin/env python3
"""
FedRAMP SCN Detector - Report Generation

Generates human-readable markdown reports and machine-readable JSON audit trails
from SCN classification results.
"""

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List


class SCNReportGenerator:
    """Generates SCN reports in multiple formats."""

    # Emoji indicators for severity
    SEVERITY_EMOJIS = {
        'IMPACT': '🔴',
        'TRANSFORMATIVE': '🟠',
        'ADAPTIVE': '🟡',
        'ROUTINE': '🟢',
        'MANUAL_REVIEW': '⚠️'
    }

    # FedRAMP notification timelines (business days)
    TIMELINES = {
        'ADAPTIVE': {'after_completion': 10},
        'TRANSFORMATIVE': {'initial_notice': 30, 'final_notice': 10, 'after_completion': 10},
        'IMPACT': {'requires_assessment': True}
    }

    def __init__(self, classifications_data: Dict, repo: str, pr_number: int,
                 run_id: str, server_url: str):
        """
        Initialize report generator.

        Args:
            classifications_data: Classifications dictionary
            repo: Repository name (org/repo)
            pr_number: Pull request number
            run_id: GitHub Actions run ID
            server_url: GitHub server URL
        """
        self.data = classifications_data
        self.classifications = classifications_data.get('classifications', [])
        self.summary = classifications_data.get('summary', {})
        self.repo = repo
        self.pr_number = pr_number
        self.run_id = run_id
        self.server_url = server_url

    def get_highest_severity(self) -> str:
        """Get highest severity category detected."""
        if self.summary.get('impact', 0) > 0:
            return 'IMPACT'
        elif self.summary.get('transformative', 0) > 0:
            return 'TRANSFORMATIVE'
        elif self.summary.get('adaptive', 0) > 0:
            return 'ADAPTIVE'
        elif self.summary.get('routine', 0) > 0:
            return 'ROUTINE'
        else:
            return 'NONE'

    def format_timeline_requirements(self, category: str) -> str:
        """Format timeline requirements for a category."""
        if category not in self.TIMELINES:
            return 'None'

        timeline = self.TIMELINES[category]

        if category == 'ADAPTIVE':
            return f"Within {timeline['after_completion']} business days after"

        elif category == 'TRANSFORMATIVE':
            return f"{timeline['initial_notice']} days initial + {timeline['final_notice']} days final"

        elif category == 'IMPACT':
            return 'N/A'

        return 'Unknown'

    def generate_summary_table(self) -> str:
        """Generate markdown summary table."""
        table = """| Category | Count | Notification Required | Timeline |
|----------|-------|----------------------|----------|
"""

        # Add rows in order: Impact → Transformative → Adaptive → Routine
        categories = [
            ('IMPACT', 'impact', 'New Assessment Required'),
            ('TRANSFORMATIVE', 'transformative', 'Yes'),
            ('ADAPTIVE', 'adaptive', 'Yes'),
            ('ROUTINE', 'routine', 'No')
        ]

        for category, key, notification in categories:
            count = self.summary.get(key, 0)
            emoji = self.SEVERITY_EMOJIS.get(category, '')
            timeline = self.format_timeline_requirements(category)

            table += f"| {emoji} **{category.capitalize()}** | {count} | {notification} | {timeline} |\n"

        return table

    def generate_category_section(self, category: str, is_pr_comment: bool = True) -> str:
        """Generate markdown section for a specific category."""
        emoji = self.SEVERITY_EMOJIS.get(category, '')
        category_lower = category.lower()
        count = self.summary.get(category_lower, 0)

        if count == 0:
            return ''

        # Get all classifications for this category
        items = [c for c in self.classifications if c.get('category') == category]

        # Section header
        if is_pr_comment:
            section = f"\n## {emoji} {category.capitalize()} Changes ({count})\n\n"
        else:
            section = f"## {emoji} {category.capitalize()} Changes ({count})\n\n"

        # Add timeline info for non-routine changes
        if category == 'TRANSFORMATIVE':
            section += "Requires **30 business days initial notice** + **10 business days final notice** + post-completion notification.\n\n"
        elif category == 'ADAPTIVE':
            section += "Requires notification **within 10 business days after completion**.\n\n"
        elif category == 'IMPACT':
            section += "**⚠️ New assessment required** - Cannot use SCN process for these changes.\n\n"

        # Add individual changes
        if category == 'ROUTINE' and count > 10:
            # Collapse routine changes if many
            if is_pr_comment:
                section += "<details>\n"
                section += f"<summary>View routine changes ({count})</summary>\n\n"

            for i, item in enumerate(items[:10], 1):
                section += self._format_change_item(item, i, brief=True)

            if count > 10:
                section += f"\n*... and {count - 10} more routine changes*\n"

            if is_pr_comment:
                section += "\n</details>\n"

        else:
            # Show all changes for non-routine or small sets
            for i, item in enumerate(items, 1):
                if is_pr_comment and count > 3:
                    # Use collapsible for many items
                    section += self._format_change_collapsible(item, i)
                else:
                    # Show directly for few items
                    section += self._format_change_item(item, i)

        return section

    def _format_change_item(self, item: Dict, index: int, brief: bool = False) -> str:
        """Format a single change item."""
        resource = item.get('resource', 'unknown')
        file_path = item.get('file', 'unknown')
        method = item.get('method', 'unknown')
        confidence = item.get('confidence', 0.0)
        reasoning = item.get('reasoning', 'No reasoning provided')

        if brief:
            return f"{index}. **{resource}** - `{file_path}`\n"

        item_md = f"\n### {index}. {resource}\n\n"
        item_md += f"**File**: `{file_path}`\n"
        item_md += f"**Classification Method**: {method.capitalize()} (confidence: {confidence*100:.0f}%)\n\n"
        item_md += f"**Reasoning**: {reasoning}\n\n"

        return item_md

    def _format_change_collapsible(self, item: Dict, index: int) -> str:
        """Format a change item with collapsible details."""
        resource = item.get('resource', 'unknown')
        file_path = item.get('file', 'unknown')
        method = item.get('method', 'unknown')
        confidence = item.get('confidence', 0.0)
        reasoning = item.get('reasoning', 'No reasoning provided')

        md = f"\n<details>\n"
        md += f"<summary>{index}. {resource} - {file_path}</summary>\n\n"
        md += f"**Classification Method**: {method.capitalize()} (confidence: {confidence*100:.0f}%)\n\n"
        md += f"**Reasoning**: {reasoning}\n\n"

        # Add rule info if available
        if 'rule_matched' in item:
            md += f"**Rule Matched**: `{item['rule_matched']}`\n\n"
        elif 'ai_model' in item:
            md += f"**AI Model**: {item['ai_model']}\n\n"

        md += "</details>\n"

        return md

    def generate_pr_comment(self) -> str:
        """Generate markdown for PR comment."""
        highest = self.get_highest_severity()
        emoji = self.SEVERITY_EMOJIS.get(highest, '')

        md = "<details>\n"
        md += "<summary>🔐 FedRAMP Significant Change Notification (SCN) Analysis</summary>\n\n"

        md += "## 📊 Change Summary\n\n"
        md += self.generate_summary_table()
        md += f"\n**Highest Severity**: {emoji} {highest.capitalize()}\n"

        # Add category sections
        for category in ['IMPACT', 'TRANSFORMATIVE', 'ADAPTIVE', 'ROUTINE']:
            section = self.generate_category_section(category, is_pr_comment=True)
            if section:
                md += f"\n---\n{section}"

        # Add manual review section if any
        manual_review_count = self.summary.get('manual_review', 0)
        if manual_review_count > 0:
            md += "\n---\n"
            md += f"\n## ⚠️ Manual Review Required ({manual_review_count})\n\n"
            md += "The following changes could not be automatically classified. Please review manually:\n\n"

            manual_items = [c for c in self.classifications if c.get('category') == 'MANUAL_REVIEW']
            for i, item in enumerate(manual_items, 1):
                md += f"{i}. **{item.get('resource')}** - `{item.get('file')}`\n"
                md += f"   Reason: {item.get('reasoning')}\n\n"

        # Add audit trail
        md += "\n---\n"
        md += self._generate_audit_section()

        # Footer
        md += "\n---\n\n"
        md += "*Generated by [Argus SCN Detector](https://github.com/huntridge-labs/argus) v0.3.0*\n\n"
        md += "</details>\n"

        return md

    def _generate_audit_section(self) -> str:
        """Generate audit trail section."""
        now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

        md = "\n## 📋 Audit Trail\n\n"
        md += f"- **Analysis Date**: {now}\n"

        if self.pr_number > 0:
            md += f"- **PR**: #{self.pr_number}\n"

        md += f"- **Configuration Version**: {self.data.get('config_version', 'default')}\n"
        md += f"- **AI Fallback Used**: {'Yes' if self.data.get('ai_enabled') else 'No'}\n"

        # Artifacts
        if self.run_id:
            artifacts_url = f"{self.server_url}/{self.repo}/actions/runs/{self.run_id}"
            md += f"\n**Artifacts**: [View Run]({artifacts_url})\n"

        return md

    def generate_audit_json(self) -> Dict:
        """Generate machine-readable audit trail JSON."""
        now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

        audit = {
            'version': '1.0',
            'analysis_metadata': {
                'timestamp': now,
                'repository': self.repo,
                'pull_request': self.pr_number if self.pr_number > 0 else None,
                'run_id': self.run_id,
                'analyzer_version': '0.3.0',
                'config_version': self.data.get('config_version', 'default')
            },
            'classifications': self.classifications,
            'summary': self.summary,
            'highest_severity': self.get_highest_severity(),
            'compliance_actions': self._generate_compliance_actions()
        }

        return audit

    def _generate_compliance_actions(self) -> List[Dict]:
        """Generate compliance action items for each category."""
        actions = []

        for category in ['ADAPTIVE', 'TRANSFORMATIVE', 'IMPACT']:
            count = self.summary.get(category.lower(), 0)
            if count == 0:
                continue

            action = {
                'category': category,
                'count': count,
                'notification_required': category != 'ROUTINE',
                'timeline': {}
            }

            if category in self.TIMELINES:
                timeline = self.TIMELINES[category]
                if 'requires_assessment' in timeline:
                    action['requires_new_assessment'] = True
                else:
                    action['timeline'] = timeline

            actions.append(action)

        return actions


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate SCN reports from classifications'
    )
    parser.add_argument(
        '--input',
        required=True,
        help='Input JSON file (from classify_changes.py)'
    )
    parser.add_argument(
        '--output-md',
        required=True,
        help='Output markdown file for PR comment'
    )
    parser.add_argument(
        '--output-json',
        required=True,
        help='Output JSON file for audit trail'
    )
    parser.add_argument(
        '--repo',
        required=True,
        help='Repository name (org/repo)'
    )
    parser.add_argument(
        '--pr-number',
        type=int,
        default=0,
        help='Pull request number'
    )
    parser.add_argument(
        '--run-id',
        required=True,
        help='GitHub Actions run ID'
    )
    parser.add_argument(
        '--server-url',
        default='https://github.com',
        help='GitHub server URL'
    )

    args = parser.parse_args()

    # Load classifications
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            classifications_data = json.load(f)
    except FileNotFoundError:
        print(f"❌ Input file not found: {args.input}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in input file: {e}", file=sys.stderr)
        return 1

    # Create generator
    generator = SCNReportGenerator(
        classifications_data,
        args.repo,
        args.pr_number,
        args.run_id,
        args.server_url
    )

    # Generate PR comment markdown
    pr_comment = generator.generate_pr_comment()
    output_md_path = Path(args.output_md)
    output_md_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_md_path, 'w', encoding='utf-8') as f:
        f.write(pr_comment)

    print(f"✅ Generated PR comment: {output_md_path}")

    # Generate audit trail JSON
    audit_json = generator.generate_audit_json()
    output_json_path = Path(args.output_json)
    output_json_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_json_path, 'w', encoding='utf-8') as f:
        json.dump(audit_json, f, indent=2)

    print(f"✅ Generated audit trail: {output_json_path}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
