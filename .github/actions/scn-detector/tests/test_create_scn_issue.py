#!/usr/bin/env python3
"""
Tests for SCN issue creation.
"""

import importlib.util
import json
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import module dynamically
REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPTS_DIR = REPO_ROOT / ".github" / "actions" / "scn-detector" / "scripts"

spec = importlib.util.spec_from_file_location(
    "create_scn_issue",
    SCRIPTS_DIR / "create_scn_issue.py"
)
create_scn_issue = importlib.util.module_from_spec(spec)
sys.modules["create_scn_issue"] = create_scn_issue
spec.loader.exec_module(create_scn_issue)


pytestmark = pytest.mark.unit


class TestSCNIssueCreatorInit:
    """Test SCNIssueCreator initialization."""

    def test_github_com_api_url(self):
        """Correct API URL for github.com."""
        creator = create_scn_issue.SCNIssueCreator(
            'token', 'org/repo', 'https://github.com'
        )
        assert creator.api_url == 'https://api.github.com'

    def test_ghes_api_url(self):
        """Correct API URL for GitHub Enterprise Server."""
        creator = create_scn_issue.SCNIssueCreator(
            'token', 'org/repo', 'https://ghes.company.com'
        )
        assert creator.api_url == 'https://ghes.company.com/api/v3'

    def test_stores_token_and_repo(self):
        """Stores token and repo correctly."""
        creator = create_scn_issue.SCNIssueCreator(
            'my-token', 'org/repo', 'https://github.com'
        )
        assert creator.github_token == 'my-token'
        assert creator.repo == 'org/repo'


class TestCalculateDueDates:
    """Test due date calculation."""

    @pytest.fixture
    def creator(self):
        """Create issue creator instance."""
        return create_scn_issue.SCNIssueCreator(
            'token', 'org/repo', 'https://github.com'
        )

    def test_adaptive_dates(self, creator):
        """ADAPTIVE has post_completion date."""
        dates = creator.calculate_due_dates('ADAPTIVE')
        assert 'post_completion' in dates

    def test_transformative_dates(self, creator):
        """TRANSFORMATIVE has multiple milestone dates."""
        dates = creator.calculate_due_dates('TRANSFORMATIVE')
        assert 'initial_notice' in dates
        assert 'final_notice' in dates
        assert 'change_execution' in dates
        assert 'post_completion' in dates

    def test_impact_dates(self, creator):
        """IMPACT requires immediate assessment."""
        dates = creator.calculate_due_dates('IMPACT')
        assert dates['assessment_required'] == 'Immediate'

    def test_routine_dates_empty(self, creator):
        """ROUTINE has no due dates."""
        dates = creator.calculate_due_dates('ROUTINE')
        assert dates == {}

    def test_dates_are_date_strings(self, creator):
        """Dates are formatted as YYYY-MM-DD."""
        dates = creator.calculate_due_dates('ADAPTIVE')
        import re
        assert re.match(r'\d{4}-\d{2}-\d{2}', dates['post_completion'])


class TestGenerateIssueTitle:
    """Test issue title generation."""

    @pytest.fixture
    def creator(self):
        return create_scn_issue.SCNIssueCreator(
            'token', 'org/repo', 'https://github.com'
        )

    def test_adaptive_title(self, creator):
        """ADAPTIVE title has emoji and category."""
        title = creator.generate_issue_title('ADAPTIVE', 'aws_instance.web')
        assert 'Adaptive' in title
        assert 'aws_instance.web' in title

    def test_transformative_title(self, creator):
        """TRANSFORMATIVE title has emoji and category."""
        title = creator.generate_issue_title('TRANSFORMATIVE', 'aws_rds.main')
        assert 'Transformative' in title

    def test_impact_title(self, creator):
        """IMPACT title has emoji and category."""
        title = creator.generate_issue_title('IMPACT', 'aws_s3.data')
        assert 'Impact' in title


class TestGenerateIssueBody:
    """Test issue body generation."""

    @pytest.fixture
    def creator(self):
        return create_scn_issue.SCNIssueCreator(
            'token', 'org/repo', 'https://github.com'
        )

    def test_body_has_change_details(self, creator):
        """Body includes resource and file details."""
        classification = {
            'category': 'ADAPTIVE',
            'resource': 'aws_instance.web',
            'file': 'main.tf',
            'method': 'rule-based',
            'confidence': 1.0,
            'reasoning': 'Instance type change',
            'operation': 'modify'
        }
        body = creator.generate_issue_body(classification, 42, '12345', {'post_completion': '2026-03-10'})

        assert 'aws_instance.web' in body
        assert 'main.tf' in body
        assert 'Adaptive' in body

    def test_body_adaptive_has_checklist(self, creator):
        """ADAPTIVE body has compliance checklist."""
        classification = {
            'category': 'ADAPTIVE',
            'resource': 'test',
            'file': 'test.tf',
            'method': 'rule-based',
            'confidence': 1.0,
            'reasoning': 'test',
            'operation': 'modify'
        }
        body = creator.generate_issue_body(
            classification, 1, '1', {'post_completion': '2026-03-10'}
        )
        assert '- [ ]' in body
        assert 'Post-Completion' in body

    def test_body_transformative_has_timeline(self, creator):
        """TRANSFORMATIVE body has full timeline."""
        classification = {
            'category': 'TRANSFORMATIVE',
            'resource': 'test',
            'file': 'test.tf',
            'method': 'rule-based',
            'confidence': 1.0,
            'reasoning': 'test',
            'operation': 'modify'
        }
        dates = {
            'initial_notice': '2026-04-01',
            'impact_analysis': '2026-04-10',
            'final_notice': '2026-04-15',
            'change_execution': '2026-04-30',
            'post_completion': '2026-05-15'
        }
        body = creator.generate_issue_body(classification, 1, '1', dates)
        assert 'Initial Notice' in body
        assert 'Final Notice' in body
        assert 'Change Execution' in body

    def test_body_impact_has_assessment(self, creator):
        """IMPACT body mentions new assessment."""
        classification = {
            'category': 'IMPACT',
            'resource': 'test',
            'file': 'test.tf',
            'method': 'rule-based',
            'confidence': 1.0,
            'reasoning': 'test',
            'operation': 'delete'
        }
        body = creator.generate_issue_body(
            classification, 1, '1', {'assessment_required': 'Immediate'}
        )
        assert 'new FedRAMP assessment' in body

    def test_body_includes_pr_link(self, creator):
        """Body links to PR when number provided."""
        classification = {
            'category': 'ADAPTIVE',
            'resource': 'test',
            'file': 'test.tf',
            'method': 'rule-based',
            'confidence': 1.0,
            'reasoning': 'test',
            'operation': 'modify'
        }
        body = creator.generate_issue_body(classification, 42, '1', {})
        assert '#42' in body


class TestCreateIssue:
    """Test GitHub API issue creation."""

    @pytest.fixture
    def creator(self):
        return create_scn_issue.SCNIssueCreator(
            'token', 'org/repo', 'https://github.com'
        )

    @patch('create_scn_issue.requests.post')
    def test_create_issue_success(self, mock_post, creator):
        """Successful issue creation returns issue number."""
        mock_response = MagicMock()
        mock_response.json.return_value = {'number': 123}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        result = creator.create_issue('Title', 'Body', ['scn'])

        assert result == 123
        mock_post.assert_called_once()

    @patch('create_scn_issue.requests.post')
    def test_create_issue_http_error(self, mock_post, creator):
        """HTTP error returns None."""
        mock_response = MagicMock()
        mock_response.text = 'Unauthorized'
        mock_post.return_value = mock_response
        mock_response.raise_for_status.side_effect = (
            __import__('requests').exceptions.HTTPError(response=mock_response)
        )

        result = creator.create_issue('Title', 'Body', ['scn'])

        assert result is None

    @patch('create_scn_issue.requests.post')
    def test_create_issue_connection_error(self, mock_post, creator):
        """Connection error returns None."""
        mock_post.side_effect = Exception("Connection refused")

        result = creator.create_issue('Title', 'Body', ['scn'])

        assert result is None


class TestCreateIssuesForClassifications:
    """Test batch issue creation from classifications."""

    @pytest.fixture
    def creator(self):
        return create_scn_issue.SCNIssueCreator(
            'token', 'org/repo', 'https://github.com'
        )

    @patch.object(create_scn_issue.SCNIssueCreator, 'create_issue')
    def test_skips_routine(self, mock_create, creator):
        """ROUTINE classifications don't create issues."""
        classifications = [
            {'category': 'ROUTINE', 'resource': 'test', 'file': 'test.tf'}
        ]

        issue_numbers, _ = creator.create_issues_for_classifications(classifications, 1, '1')

        mock_create.assert_not_called()
        assert issue_numbers == []

    @patch.object(create_scn_issue.SCNIssueCreator, 'create_issue')
    def test_creates_for_adaptive(self, mock_create, creator):
        """ADAPTIVE classifications create issues."""
        mock_create.return_value = 100
        classifications = [
            {
                'category': 'ADAPTIVE',
                'resource': 'aws_instance.web',
                'file': 'main.tf',
                'method': 'rule-based',
                'confidence': 1.0,
                'reasoning': 'test',
                'operation': 'modify'
            }
        ]

        issue_numbers, _ = creator.create_issues_for_classifications(classifications, 1, '1')

        assert issue_numbers == [100]
        mock_create.assert_called_once()

    @patch.object(create_scn_issue.SCNIssueCreator, 'create_issue')
    def test_mixed_classifications(self, mock_create, creator):
        """Only non-routine classifications create issues."""
        mock_create.side_effect = [101, 102]
        classifications = [
            {'category': 'ROUTINE', 'resource': 'r1', 'file': 'f1'},
            {
                'category': 'ADAPTIVE',
                'resource': 'r2',
                'file': 'f2',
                'method': 'rule-based',
                'confidence': 1.0,
                'reasoning': 'test',
                'operation': 'modify'
            },
            {
                'category': 'IMPACT',
                'resource': 'r3',
                'file': 'f3',
                'method': 'rule-based',
                'confidence': 1.0,
                'reasoning': 'test',
                'operation': 'delete'
            }
        ]

        issue_numbers, _ = creator.create_issues_for_classifications(classifications, 1, '1')

        assert len(issue_numbers) == 2
        assert mock_create.call_count == 2

    @patch.object(create_scn_issue.SCNIssueCreator, 'create_issue')
    def test_empty_classifications(self, mock_create, creator):
        """Empty classification list creates no issues."""
        issue_numbers, _ = creator.create_issues_for_classifications([], 1, '1')

        assert issue_numbers == []
        mock_create.assert_not_called()
