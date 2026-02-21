#!/usr/bin/env python3
"""
FedRAMP SCN Detector - GitHub Issue Creation

Creates GitHub Issues for Adaptive, Transformative, and Impact changes
with compliance timelines and tracking checklists.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set

import requests


class SCNIssueCreator:
    """Creates GitHub Issues for SCN tracking."""

    # Issue labels by category
    CATEGORY_LABELS = {
        'ADAPTIVE': ['scn', 'scn:adaptive', 'compliance'],
        'TRANSFORMATIVE': ['scn', 'scn:transformative', 'compliance'],
        'IMPACT': ['scn', 'scn:impact', 'compliance']
    }

    # Emoji indicators
    CATEGORY_EMOJIS = {
        'ADAPTIVE': '🟡',
        'TRANSFORMATIVE': '🟠',
        'IMPACT': '🔴'
    }

    def __init__(self, github_token: str, repo: str, server_url: str = 'https://github.com'):
        """
        Initialize issue creator.

        Args:
            github_token: GitHub API token
            repo: Repository name (org/repo)
            server_url: GitHub server URL
        """
        self.github_token = github_token
        self.repo = repo
        self.server_url = server_url
        self.api_url = server_url.replace('://github.com', '://api.github.com').replace('://www.github.com', '://api.github.com')

        # If not github.com, assume GHES with /api/v3 path
        if 'api.github.com' not in self.api_url:
            self.api_url = f"{server_url}/api/v3"

    @staticmethod
    def _get_nth_weekday(year: int, month: int, weekday: int, n: int) -> datetime:
        """
        Get the nth occurrence of a weekday in a month.
        
        Args:
            year: Year
            month: Month (1-12)
            weekday: Day of week (0=Monday, 6=Sunday)
            n: Which occurrence (1=first, 2=second, etc.)
            
        Returns:
            datetime object for that day
        """
        first = datetime(year, month, 1)
        # Days until the first occurrence of the target weekday
        if first.weekday() == weekday:
            first_occurrence = first
        else:
            days_ahead = (weekday - first.weekday()) % 7
            first_occurrence = first + timedelta(days=days_ahead)
        # Add (n-1) weeks to get the nth occurrence
        return first_occurrence + timedelta(weeks=(n - 1))

    def get_us_federal_holidays(self, year: int) -> Set[datetime]:
        """
        Get US federal holidays for a given year.
        
        Args:
            year: Year to get holidays for
            
        Returns:
            Set of date objects for federal holidays (date only, no time)
        """
        holidays = set()
        
        # Fixed-date holidays (date only, no time component)
        holidays.add(datetime(year, 1, 1).date())   # New Year's Day
        holidays.add(datetime(year, 7, 4).date())   # Independence Day
        holidays.add(datetime(year, 11, 11).date()) # Veterans Day
        holidays.add(datetime(year, 12, 25).date()) # Christmas Day
        
        # Martin Luther King Jr. Day - 3rd Monday in January
        holidays.add(self._get_nth_weekday(year, 1, 0, 3).date())
        
        # Presidents' Day - 3rd Monday in February
        holidays.add(self._get_nth_weekday(year, 2, 0, 3).date())
        
        # Memorial Day - Last Monday in May
        # Using backward calculation from May 31 since we need the LAST Monday
        # (May can have 4 or 5 Mondays depending on the year)
        # weekday() returns 0 for Monday, so if May 31 is Monday, we get 0 % 7 = 0 (correct: May 31)
        # If May 31 is Tuesday-Sunday (1-6), we subtract that many days to get previous Monday
        may_31 = datetime(year, 5, 31)
        days_back_to_monday = may_31.weekday() % 7
        holidays.add((may_31 - timedelta(days=days_back_to_monday)).date())
        
        # Labor Day - 1st Monday in September
        holidays.add(self._get_nth_weekday(year, 9, 0, 1).date())
        
        # Columbus Day - 2nd Monday in October
        holidays.add(self._get_nth_weekday(year, 10, 0, 2).date())
        
        # Thanksgiving Day - 4th Thursday in November
        holidays.add(self._get_nth_weekday(year, 11, 3, 4).date())
        
        return holidays

    def calculate_due_dates(self, category: str) -> Dict[str, str]:
        """
        Calculate compliance due dates for a category.

        Args:
            category: SCN category

        Returns:
            Dictionary of due dates
        """
        today = datetime.now()
        
        # Get federal holidays for current and next year
        current_year_holidays = self.get_us_federal_holidays(today.year)
        next_year_holidays = self.get_us_federal_holidays(today.year + 1)
        all_holidays = current_year_holidays | next_year_holidays

        # Business days calculation (excludes weekends and US federal holidays)
        def add_business_days(start_date: datetime, days: int) -> str:
            current = start_date
            added = 0

            while added < days:
                current += timedelta(days=1)
                # Skip weekends and federal holidays (compare dates only)
                if current.weekday() < 5 and current.date() not in all_holidays:
                    added += 1

            return current.strftime('%Y-%m-%d')

        if category == 'ADAPTIVE':
            # Within 10 business days after completion
            return {
                'post_completion': add_business_days(today, 10)
            }

        elif category == 'TRANSFORMATIVE':
            # 30 days initial, 10 days final, 10 days after
            initial_date = add_business_days(today, 30)
            final_date = add_business_days(datetime.strptime(initial_date, '%Y-%m-%d'), 20)
            execution_date = add_business_days(datetime.strptime(final_date, '%Y-%m-%d'), 10)
            post_completion_date = add_business_days(datetime.strptime(execution_date, '%Y-%m-%d'), 10)

            return {
                'initial_notice': initial_date,
                'impact_analysis': add_business_days(datetime.strptime(initial_date, '%Y-%m-%d'), 8),
                'final_notice': final_date,
                'change_execution': execution_date,
                'post_completion': post_completion_date
            }

        elif category == 'IMPACT':
            # Requires new assessment
            return {
                'assessment_required': 'Immediate'
            }

        return {}

    def generate_issue_title(self, category: str, resource: str) -> str:
        """Generate issue title."""
        emoji = self.CATEGORY_EMOJIS.get(category, '')
        return f"{emoji} FedRAMP SCN: {category.capitalize()} Change - {resource}"

    def generate_issue_body(self, classification: Dict, pr_number: int,
                            run_id: str, due_dates: Dict[str, str]) -> str:
        """
        Generate issue body markdown.

        Args:
            classification: Classification dictionary
            pr_number: Pull request number
            run_id: GitHub Actions run ID
            due_dates: Dictionary of due dates

        Returns:
            Issue body markdown
        """
        category = classification.get('category')
        emoji = self.CATEGORY_EMOJIS.get(category, '')
        resource = classification.get('resource', 'unknown')
        file_path = classification.get('file', 'unknown')
        method = classification.get('method', 'unknown')
        confidence = classification.get('confidence', 0.0)
        reasoning = classification.get('reasoning', 'No reasoning provided')

        today = datetime.now().strftime('%Y-%m-%d')

        body = f"## {emoji} FedRAMP Significant Change Notification\n\n"
        body += f"**Category**: {emoji} {category.capitalize()}\n"

        if pr_number > 0:
            body += f"**PR**: #{pr_number}\n"

        body += f"**Detection Date**: {today}\n\n"

        body += "---\n\n"
        body += "### Change Details\n\n"
        body += f"**Resource**: `{resource}`\n"
        body += f"**File**: `{file_path}`\n"
        body += f"**Operation**: {classification.get('operation', 'unknown').capitalize()}\n"
        body += f"**Confidence**: {confidence*100:.0f}% ({method.capitalize()})\n\n"

        # Attributes changed
        attrs = classification.get('attributes_changed', [])
        if attrs:
            body += "**Attributes Changed**:\n"
            for attr in attrs:
                body += f"- `{attr}`\n"
            body += "\n"

        body += f"**Classification Reasoning**:\n{reasoning}\n\n"

        body += "---\n\n"

        # Category-specific timelines
        if category == 'ADAPTIVE':
            body += "### FedRAMP Compliance Timeline\n\n"
            body += "- [ ] **Change Execution** - Complete the infrastructure change\n"
            body += f"- [ ] **Post-Completion Notification** - Due: {due_dates.get('post_completion')} (within 10 business days after)\n\n"

        elif category == 'TRANSFORMATIVE':
            body += "### FedRAMP Compliance Timeline\n\n"
            body += f"- [ ] **Initial Notice** - Due: {due_dates.get('initial_notice')} (30 business days before change)\n"
            body += f"- [ ] **Impact Analysis** - Due: {due_dates.get('impact_analysis')} (before final notice)\n"
            body += f"- [ ] **Final Notice** - Due: {due_dates.get('final_notice')} (10 business days before change)\n"
            body += f"- [ ] **Change Execution** - Target: {due_dates.get('change_execution')}\n"
            body += f"- [ ] **Post-Completion Notification** - Due: {due_dates.get('post_completion')} (within 10 business days after)\n\n"

        elif category == 'IMPACT':
            body += "### ⚠️ Impact Categorization Change\n\n"
            body += "**This change requires a new FedRAMP assessment and cannot use the SCN process.**\n\n"
            body += "- [ ] **Assess Impact** - Determine if this truly changes security boundary or FIPS level\n"
            body += "- [ ] **Notify FedRAMP** - Contact FedRAMP immediately\n"
            body += "- [ ] **Initiate Re-Assessment** - Begin new authorization process\n"
            body += "- [ ] **Document Changes** - Update System Security Plan (SSP)\n\n"

        body += "---\n\n"
        body += "### Required Documentation\n\n"

        if category in ['ADAPTIVE', 'TRANSFORMATIVE']:
            body += "- [ ] Change description and justification\n"
            body += "- [ ] Risk analysis and mitigation plan\n"
            body += "- [ ] Test results and validation evidence\n"
            body += "- [ ] Rollback plan\n"

            if category == 'TRANSFORMATIVE':
                body += "- [ ] Customer communication (if opt-out available)\n"
                body += "- [ ] Security impact assessment\n"

        elif category == 'IMPACT':
            body += "- [ ] Updated System Security Plan (SSP)\n"
            body += "- [ ] Security impact analysis\n"
            body += "- [ ] New authorization package\n"
            body += "- [ ] FedRAMP communication records\n"

        body += "\n---\n\n"
        body += "### Artifacts\n\n"

        if run_id:
            artifacts_url = f"{self.server_url}/{self.repo}/actions/runs/{run_id}"
            body += f"- [Full Analysis Report]({artifacts_url})\n"

        if pr_number > 0:
            pr_url = f"{self.server_url}/{self.repo}/pull/{pr_number}"
            body += f"- [Pull Request #{pr_number}]({pr_url})\n"

        body += "\n---\n\n"
        body += "*This issue was automatically created by [Argus SCN Detector](https://github.com/huntridge-labs/argus). "
        body += "For questions, see [FedRAMP SCN Documentation](https://www.fedramp.gov/docs/20x/significant-change-notifications/).*\n"

        return body

    def create_issue(self, title: str, body: str, labels: List[str]) -> Optional[int]:
        """
        Create GitHub Issue.

        Args:
            title: Issue title
            body: Issue body (markdown)
            labels: List of labels

        Returns:
            Issue number if successful, None otherwise
        """
        url = f"{self.api_url}/repos/{self.repo}/issues"

        headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json'
        }

        data = {
            'title': title,
            'body': body,
            'labels': labels
        }

        try:
            response = requests.post(url, headers=headers, json=data, timeout=30)
            response.raise_for_status()

            issue_data = response.json()
            issue_number = issue_data.get('number')

            print(f"  ✅ Created issue #{issue_number}: {title}")

            return issue_number

        except requests.exceptions.HTTPError as e:
            print(f"  ❌ Failed to create issue: {e}", file=sys.stderr)
            print(f"     Response: {e.response.text}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"  ❌ Error creating issue: {e}", file=sys.stderr)
            return None

    def create_issues_for_classifications(self, classifications: List[Dict],
                                          pr_number: int, run_id: str) -> List[int]:
        """
        Create issues for all relevant classifications.

        Args:
            classifications: List of classification dictionaries
            pr_number: Pull request number
            run_id: GitHub Actions run ID

        Returns:
            List of created issue numbers
        """
        print("📋 Creating GitHub Issues for SCN tracking...")

        issue_numbers = []

        # Group by category
        grouped = {}
        for classification in classifications:
            category = classification.get('category')

            # Only create issues for Adaptive, Transformative, Impact
            if category not in ['ADAPTIVE', 'TRANSFORMATIVE', 'IMPACT']:
                continue

            if category not in grouped:
                grouped[category] = []

            grouped[category].append(classification)

        # Create issues
        for category, items in grouped.items():
            print(f"\n{self.CATEGORY_EMOJIS.get(category, '')} {category.capitalize()} changes: {len(items)}")

            for classification in items:
                resource = classification.get('resource', 'unknown')
                due_dates = self.calculate_due_dates(category)

                title = self.generate_issue_title(category, resource)
                body = self.generate_issue_body(classification, pr_number, run_id, due_dates)
                labels = self.CATEGORY_LABELS.get(category, ['scn'])

                issue_number = self.create_issue(title, body, labels)

                if issue_number:
                    issue_numbers.append(issue_number)

        if issue_numbers:
            print(f"\n✅ Created {len(issue_numbers)} issue(s)")
        else:
            print("\nℹ️  No issues created (may be routine changes only)")

        return issue_numbers


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Create GitHub Issues for SCN tracking'
    )
    parser.add_argument(
        '--input',
        required=True,
        help='Input JSON file (from classify_changes.py)'
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
    parser.add_argument(
        '--output',
        help='Output file for issue numbers (comma-separated)'
    )

    args = parser.parse_args()

    # Get GitHub token
    github_token = os.environ.get('GITHUB_TOKEN')
    if not github_token:
        print("❌ GITHUB_TOKEN environment variable not set", file=sys.stderr)
        return 1

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

    # Create issue creator
    creator = SCNIssueCreator(github_token, args.repo, args.server_url)

    # Create issues
    classifications = classifications_data.get('classifications', [])
    issue_numbers = creator.create_issues_for_classifications(
        classifications,
        args.pr_number,
        args.run_id
    )

    # Write output if requested
    if args.output and issue_numbers:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(','.join(str(n) for n in issue_numbers))

        print(f"\n✅ Issue numbers written to: {output_path}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
