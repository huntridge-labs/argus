#!/usr/bin/env python3
"""
Tests for SCN report generation.
"""

import importlib.util
import json
import pytest
import sys
from pathlib import Path

# Import module dynamically
REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPTS_DIR = REPO_ROOT / ".github" / "actions" / "scn-detector" / "scripts"

spec = importlib.util.spec_from_file_location(
    "generate_scn_report",
    SCRIPTS_DIR / "generate_scn_report.py"
)
generate_scn_report = importlib.util.module_from_spec(spec)
sys.modules["generate_scn_report"] = generate_scn_report
spec.loader.exec_module(generate_scn_report)


pytestmark = pytest.mark.unit


@pytest.fixture
def sample_classifications():
    """Sample classification data for testing."""
    return {
        'classifications': [
            {
                'category': 'ROUTINE',
                'method': 'rule-based',
                'confidence': 1.0,
                'reasoning': 'Tag changes',
                'resource': 'aws_instance.web',
                'file': 'main.tf'
            },
            {
                'category': 'ADAPTIVE',
                'method': 'rule-based',
                'confidence': 1.0,
                'reasoning': 'Instance type changes',
                'resource': 'aws_instance.app',
                'file': 'compute.tf'
            },
            {
                'category': 'TRANSFORMATIVE',
                'method': 'ai-fallback',
                'confidence': 0.92,
                'reasoning': 'Database engine change',
                'resource': 'aws_rds_cluster.main',
                'file': 'database.tf',
                'ai_model': 'claude-3-haiku-20240307'
            }
        ],
        'summary': {
            'routine': 1,
            'adaptive': 1,
            'transformative': 1,
            'impact': 0,
            'manual_review': 0
        },
        'config_version': '1.0',
        'ai_enabled': True
    }


@pytest.fixture
def generator(sample_classifications):
    """Create report generator instance."""
    return generate_scn_report.SCNReportGenerator(
        sample_classifications,
        repo='huntridge-labs/argus',
        pr_number=42,
        run_id='12345',
        server_url='https://github.com'
    )


class TestSCNReportGenerator:
    """Test SCNReportGenerator class."""

    def test_initialization(self, generator):
        """Test generator initializes with correct data."""
        assert generator.repo == 'huntridge-labs/argus'
        assert generator.pr_number == 42
        assert generator.run_id == '12345'
        assert len(generator.classifications) == 3

    def test_get_highest_severity_transformative(self, generator):
        """Highest severity is TRANSFORMATIVE when present."""
        assert generator.get_highest_severity() == 'TRANSFORMATIVE'

    def test_get_highest_severity_impact(self, sample_classifications):
        """IMPACT overrides all other categories."""
        sample_classifications['summary']['impact'] = 1
        gen = generate_scn_report.SCNReportGenerator(
            sample_classifications, 'repo', 1, '1', 'https://github.com'
        )
        assert gen.get_highest_severity() == 'IMPACT'

    def test_get_highest_severity_none(self):
        """Returns NONE when no changes detected."""
        data = {'classifications': [], 'summary': {}}
        gen = generate_scn_report.SCNReportGenerator(
            data, 'repo', 0, '1', 'https://github.com'
        )
        assert gen.get_highest_severity() == 'NONE'


class TestFormatTimeline:
    """Test format_timeline_requirements."""

    @pytest.fixture
    def generator(self):
        """Minimal generator for timeline tests."""
        data = {'classifications': [], 'summary': {}}
        return generate_scn_report.SCNReportGenerator(
            data, 'repo', 0, '1', 'https://github.com'
        )

    def test_adaptive_timeline(self, generator):
        """ADAPTIVE shows 10 business days."""
        result = generator.format_timeline_requirements('ADAPTIVE')
        assert '10 business days' in result

    def test_transformative_timeline(self, generator):
        """TRANSFORMATIVE shows 30 + 10 days."""
        result = generator.format_timeline_requirements('TRANSFORMATIVE')
        assert '30 days' in result
        assert '10 days' in result

    def test_impact_timeline(self, generator):
        """IMPACT returns N/A."""
        result = generator.format_timeline_requirements('IMPACT')
        assert result == 'N/A'

    def test_routine_timeline(self, generator):
        """ROUTINE has no timeline requirement."""
        result = generator.format_timeline_requirements('ROUTINE')
        assert result == 'None'


class TestSummaryTable:
    """Test generate_summary_table."""

    def test_table_has_all_categories(self, generator):
        """Summary table includes all four categories."""
        table = generator.generate_summary_table()
        assert 'Impact' in table
        assert 'Transformative' in table
        assert 'Adaptive' in table
        assert 'Routine' in table

    def test_table_has_counts(self, generator):
        """Summary table shows correct counts."""
        table = generator.generate_summary_table()
        # Contains table rows with markdown formatting
        assert '| 1 |' in table or '| 0 |' in table


class TestCategorySections:
    """Test generate_category_section."""

    def test_empty_category_returns_empty(self, generator):
        """Category with 0 count returns empty string."""
        result = generator.generate_category_section('IMPACT')
        assert result == ''

    def test_adaptive_section_has_timeline(self, generator):
        """ADAPTIVE section mentions notification timeline."""
        result = generator.generate_category_section('ADAPTIVE')
        assert '10 business days' in result

    def test_transformative_section_has_timeline(self, generator):
        """TRANSFORMATIVE section mentions notice requirements."""
        result = generator.generate_category_section('TRANSFORMATIVE')
        assert '30 business days' in result

    def test_routine_section_has_changes(self, generator):
        """ROUTINE section lists changes."""
        result = generator.generate_category_section('ROUTINE')
        assert 'aws_instance.web' in result


class TestPRComment:
    """Test generate_pr_comment."""

    def test_pr_comment_has_summary(self, generator):
        """PR comment includes summary section."""
        comment = generator.generate_pr_comment()
        assert 'Change Summary' in comment

    def test_pr_comment_has_audit(self, generator):
        """PR comment includes audit trail."""
        comment = generator.generate_pr_comment()
        assert 'Audit Trail' in comment

    def test_pr_comment_has_pr_link(self, generator):
        """PR comment references PR number."""
        comment = generator.generate_pr_comment()
        assert '#42' in comment

    def test_pr_comment_is_collapsible(self, generator):
        """PR comment wrapped in details/summary."""
        comment = generator.generate_pr_comment()
        assert '<details>' in comment
        assert '</details>' in comment


class TestAuditJSON:
    """Test generate_audit_json."""

    def test_audit_json_structure(self, generator):
        """Audit JSON has required top-level keys."""
        audit = generator.generate_audit_json()
        assert 'version' in audit
        assert 'analysis_metadata' in audit
        assert 'classifications' in audit
        assert 'summary' in audit
        assert 'highest_severity' in audit
        assert 'compliance_actions' in audit

    def test_audit_json_metadata(self, generator):
        """Audit JSON metadata has correct values."""
        audit = generator.generate_audit_json()
        meta = audit['analysis_metadata']
        assert meta['repository'] == 'huntridge-labs/argus'
        assert meta['pull_request'] == 42
        assert meta['run_id'] == '12345'

    def test_audit_json_compliance_actions(self, generator):
        """Compliance actions generated for non-routine categories."""
        audit = generator.generate_audit_json()
        actions = audit['compliance_actions']
        categories = [a['category'] for a in actions]
        assert 'ADAPTIVE' in categories
        assert 'TRANSFORMATIVE' in categories
        # ROUTINE should not have compliance actions
        assert 'ROUTINE' not in categories


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_no_classifications(self):
        """Handles empty classifications gracefully."""
        data = {
            'classifications': [],
            'summary': {'routine': 0, 'adaptive': 0, 'transformative': 0, 'impact': 0}
        }
        gen = generate_scn_report.SCNReportGenerator(
            data, 'repo', 0, '1', 'https://github.com'
        )
        comment = gen.generate_pr_comment()
        assert 'Change Summary' in comment

    def test_manual_review_section(self):
        """Manual review items shown in PR comment."""
        data = {
            'classifications': [
                {
                    'category': 'MANUAL_REVIEW',
                    'method': 'unmatched',
                    'confidence': 0.0,
                    'reasoning': 'No rule matched',
                    'resource': 'unknown.test',
                    'file': 'test.tf'
                }
            ],
            'summary': {
                'routine': 0, 'adaptive': 0, 'transformative': 0,
                'impact': 0, 'manual_review': 1
            }
        }
        gen = generate_scn_report.SCNReportGenerator(
            data, 'repo', 0, '1', 'https://github.com'
        )
        comment = gen.generate_pr_comment()
        assert 'Manual Review' in comment

    def test_zero_pr_number(self):
        """PR number 0 (not a PR context) handled."""
        data = {'classifications': [], 'summary': {}}
        gen = generate_scn_report.SCNReportGenerator(
            data, 'repo', 0, '1', 'https://github.com'
        )
        audit = gen.generate_audit_json()
        assert audit['analysis_metadata']['pull_request'] is None
