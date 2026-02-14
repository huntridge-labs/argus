# Contributing to Tests

This guide helps you add or modify tests when contributing to hardening-workflows.

## Quick Start

**TL;DR**: Create a `test_*.py` file in `.github/actions/YOUR_ACTION/tests/` using pytest and it will be automatically discovered. No configuration needed! 🎉

### Prerequisites

```bash
# Install Python dependencies
pip install -r requirements.txt

# Verify setup
pytest
```

## Test Structure

We use a **co-located pytest approach**:
- **Unit tests** (<30s) for scripts and parsers - **co-located with actions**
  - **Python tests**: Using pytest (110+ tests across all actions)
- **Schema validation** (174 tests) for composite actions - in `tests/unit/actions/`
- **Shared fixtures** - in `tests/fixtures/` reused across all tests
- **Integration tests** (16+ jobs in test-actions.yml) for end-to-end action validation
- **Total test coverage**: 300+ tests across all layers

```
.github/actions/
├── scanner-*/
│   ├── action.yml
│   ├── scripts/               # Parser & summary scripts (Python)
│   │   ├── parse-results.py
│   │   └── generate-summary.py
│   └── tests/                 # Co-located pytest tests
│       ├── test_parse_results.py
│       ├── test_generate_summary.py
│       └── conftest.py (optional, for shared fixtures/setup)
├── parse-*/
│   ├── scripts/               # Config parsers (Python)
│   │   └── parse_config.py
│   └── tests/                 # Co-located pytest tests
│       └── test_parse_config.py

tests/
├── fixtures/                  # Shared synthetic test data
│   ├── scanner-outputs/       # Mock scanner results
│   ├── test-apps/             # Minimal test applications
│   └── configs/               # Test configuration files
├── unit/actions/              # Action schema validation
└── CONTRIBUTING.md            # ← You are here
```

**Key Principles**:
- ✅ Tests live with the code they test (co-located in action directories)
- ✅ **Automatic discovery** - pytest finds all `test_*.py` files, no config updates needed
- ✅ Shared fixtures - multiple actions reuse mock data from `tests/fixtures/`
- ✅ pytest fixtures and parametrize for DRY tests

## Running Tests Locally

```bash
# All tests with coverage (recommended)
pytest

# Fast validation without coverage (<10s)
pytest --no-cov -q

# Individual test suites
pytest .github/actions/scanner-bandit/tests/  # Single action tests
pytest tests/unit/actions/                    # Schema validation
pytest --collect-only                         # List all tests

# Single test file (pytest)
pytest .github/actions/scanner-container/tests/test_parse_trivy_results.py -v
```

**Current Status**: 300+ tests passing (110+ pytest tests + 174 schema validation + 16+ integration jobs)

## When to Add/Update Tests

### Scenario 1: Adding a New Scanner Action with Parser Script

**Files**:
- `.github/actions/scanner-myScanner/action.yml`
- `.github/actions/scanner-myScanner/scripts/parse-results.py`
- `.github/actions/scanner-myScanner/scripts/generate-summary.py`

**Add**: `.github/actions/scanner-myScanner/tests/test_parse_results.py`

**✨ No configuration needed!** Tests are automatically discovered by pytest:
- `pytest` - Finds all `test_*.py` files in `.github/actions/*/tests/`
- Coverage automatically included with `--cov`

**Pattern** (pytest format - copy from existing scanner action test):
```python
import pytest
from pathlib import Path
import json
from ..scripts.parse_results import parse_counts

# Fixtures directory
FIXTURES_DIR = Path(__file__).parent.parent.parent.parent.parent / "tests" / "fixtures" / "scanner-outputs" / "myScanner"

@pytest.mark.parametrize("fixture_file,expected", [
    ("results-zero-findings.json", (0, 0, 0, 0)),
    ("results-with-findings.json", (1, 2, 3, 4)),
])
def test_parse_counts(fixture_file, expected):
    """Test parsing severity counts from scanner output."""
    report_file = FIXTURES_DIR / fixture_file
    result = parse_counts(str(report_file))
    assert result == expected

def test_parse_counts_missing_file():
    """Test handling of missing report file."""
    result = parse_counts("/nonexistent/file.json")
    assert result == (0, 0, 0, 0)

def test_parse_counts_malformed_json(tmp_path):
    """Test handling of malformed JSON."""
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{invalid json}")
    result = parse_counts(str(bad_json))
    assert result == (0, 0, 0, 0)
```

**Why pytest?**
- Industry standard testing framework
- Fixtures and parametrize for DRY tests
- Clear assertion syntax
- Automatic discovery - no config needed
- Integrated coverage reporting with pytest-cov
- Rich output and debugging features

**Shared Fixture**: Add to `tests/fixtures/scanner-outputs/myScanner/results-with-findings.json`

**Why shared?** Multiple tests may need the same mock data, so fixtures remain centralized in `tests/fixtures/`

**Test Discovery**:
Place your `test_*.py` file anywhere in `.github/actions/*/tests/test_*.py` and pytest will automatically discover it:
```bash
# These all work automatically:
.github/actions/scanner-myScanner/tests/test_parse_results.py
.github/actions/scanner-myScanner/tests/test_generate_summary.py
.github/actions/scanner-foo/tests/test_parser.py
```

### Scenario 2: Adding a New Composite Action

**File**: `.github/actions/scanner-myScanner/action.yml`

**Required**:
- All inputs must have `description`
- All outputs must have `description`
- Steps with `run:` must specify `shell: bash`

**Validation**: Automatically tested by `validate-action-schemas.py`

**Add integration test**:
- Add to `.github/workflows/test-actions.yml` matrix with appropriate scanner name

### Scenario 3: Modifying an Existing Script

**Before committing**:
1. Run the relevant test: `bash .github/actions/scanner-X/tests/test-parse-results.sh`
2. If test fails, update test to match new behavior
3. If script output format changes, update shared fixtures in `tests/fixtures/`

### Scenario 4: Bug Fix in Script

**Steps**:
1. Add a test that reproduces the bug (should fail)
2. Fix the bug
3. Verify test passes
4. Commit both test and fix together

## Test Patterns & Examples

### Python Test Template (pytest)

**See existing tests for full examples:**
- `.github/actions/scanner-container/tests/test_parse_trivy_results.py`
- `.github/actions/scanner-bandit/tests/test_parse_results.py`

```python
import pytest
from pathlib import Path
import json
import sys
import os

# Add parent scripts dir to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'scripts'))

from parse_results import parse_counts
from generate_summary import generate_summary

# Fixtures directory - navigate from test file to repo root
FIXTURES = Path(__file__).parent.parent.parent.parent.parent / "tests" / "fixtures"

class TestParseResults:
    """Test suite for parse-results.py"""

    @pytest.fixture
    def fixtures_dir(self):
        return FIXTURES / "scanner-outputs" / "myScanner"

    @pytest.mark.parametrize("fixture_file,expected", [
        ("results-zero-findings.json", (0, 0, 0, 0)),
        ("results-with-findings.json", (1, 2, 3, 4)),
        ("results-edge-cases.json", (5, 10, 3, 2)),
    ])
    def test_parse_counts(self, fixtures_dir, fixture_file, expected):
        """Test parsing counts from various fixture files."""
        report_file = fixtures_dir / fixture_file
        result = parse_counts(str(report_file))
        assert result == expected

    def test_parse_counts_missing_file(self):
        """Test graceful handling of missing report file."""
        result = parse_counts("/nonexistent/file.json")
        assert result == (0, 0, 0, 0)

    def test_parse_counts_malformed_json(self, tmp_path):
        """Test handling of malformed JSON."""
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{invalid json")
        result = parse_counts(str(bad_json))
        assert result == (0, 0, 0, 0)

class TestGenerateSummary:
    """Test suite for generate-summary.py"""

    def test_summary_generation(self, tmp_path, monkeypatch):
        """Test markdown summary generation."""
        output_file = tmp_path / "summary.md"

        # Mock environment variables
        monkeypatch.setenv("CRITICAL", "1")
        monkeypatch.setenv("HIGH", "2")
        monkeypatch.setenv("MEDIUM", "3")
        monkeypatch.setenv("LOW", "4")
        monkeypatch.setenv("TOTAL", "10")
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
        monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
        monkeypatch.setenv("GITHUB_RUN_ID", "12345")

        generate_summary(str(output_file), is_pr_comment=False)

        content = output_file.read_text()
        assert "## 🔍" in content
        assert "1" in content  # critical count
        assert "View Reports" in content
```

**pytest features used:**
- `@pytest.fixture` - Setup/teardown for tests
- `@pytest.mark.parametrize` - Run same test with multiple inputs
- `@pytest.fixture` - Monkeypatch environment variables
- `tmp_path` - Temporary directory for file tests
- Class-based organization - Group related tests

**Note**: Fixtures are in repo root at `tests/fixtures/`, so tests in `.github/actions/*/tests/` navigate up to reach them.

## Updating Fixtures

### Adding a New Fixture File

1. **Create synthetic data** (not real vulnerabilities!)
2. Place in `tests/fixtures/scanner-outputs/{scanner-name}/`
3. Use consistent naming:
   - `results-with-findings.json` (has vulnerabilities)
   - `results-zero-findings.json` (clean scan)
   - `results-baseline-scan.json` (specific scan type)

### Regenerating Fixtures

```bash
# DO NOT include real vulnerabilities
# Use redacted/synthetic data only

# Example: Creating a Trivy fixture
trivy image --format json alpine:3.18 > results.json
# Manually edit to remove/redact sensitive info
# Keep structure but use safe CVE examples
```

## Common Pitfalls

❌ **Don't**: Use real vulnerabilities in fixtures
✅ **Do**: Use synthetic/redacted data

❌ **Don't**: Skip tests when modifying scripts
✅ **Do**: Run tests before committing: `pytest`

❌ **Don't**: Hard-code absolute paths
✅ **Do**: Use relative paths from repo root or pytest fixtures

❌ **Don't**: Commit broken tests
✅ **Do**: Fix or skip (with `@pytest.mark.skip`) failing tests

❌ **Don't**: Import scripts without sys.path manipulation
✅ **Do**: Use `sys.path.insert(0, str(Path(__file__).parent.parent / 'scripts'))`

❌ **Don't**: Forget to handle environment variables in tests
✅ **Do**: Use `monkeypatch` fixture to set/mock env vars

## CI/CD Integration

Tests run automatically on:
- Every push to any branch
- Every pull request

### Test Workflows Overview

| Workflow | Triggers On | Tests |
|----------|-------------|-------|
| `test-unit.yml` | Any PR / push to main | Unit tests (bash/JS/Python), coverage |
| `test-actions.yml` | Changes to `.github/actions/**` | Integration tests for all composite actions (16+ jobs) |

### Understanding Integration Test Results

When a PR changes composite actions, `test-actions.yml` runs:

```
┌─────────────────────────────────────────────────────────┐
│ Composite Actions Test Summary                          │
├──────────────────────────┬──────────────────────────────┤
│ Category                 │ Status                       │
├──────────────────────────┼──────────────────────────────┤
│ SAST Scanners            │ ✅ success                   │
│ CodeQL                   │ ✅ success                   │
│ Secrets Detection        │ ✅ success                   │
│ Infrastructure (IaC)     │ ✅ success                   │
│ Container Scanners       │ ✅ success                   │
│ ZAP DAST                 │ ✅ success                   │
│ Linters                  │ ✅ success                   │
│ ClamAV Malware           │ ✅ success                   │
│ Config Parsers           │ ✅ success                   │
│ Security Summary         │ ✅ success                   │
└──────────────────────────┴──────────────────────────────┘
```

**To debug a failure:**
1. Click the failed job name (e.g., "IaC / checkov")
2. Expand step logs to see the actual error
3. Most failures are input mismatches or missing dependencies

### Adding Your Action to Integration Tests

If you create a new action, add it to the appropriate matrix in `.github/workflows/test-actions.yml`:

```yaml
# Example: Adding scanner-newscan to SAST tests
strategy:
  matrix:
    scanner:
      - bandit
      - opengrep
      - newscan          # ← Add here
    include:
      - scanner: newscan
        fixture: tests/fixtures/test-apps/python-app
        action_path: .github/actions/scanner-newscan
```

**Pre-commit hooks** run:
- Whitespace cleanup
- YAML/JSON validation
- Secret scanning

**GitHub Actions workflow**: `.github/workflows/test-unit.yml`

## Getting Help

- **See existing tests**: Best examples are in `tests/unit/bash/test-parse-*.sh`
- **Phase 2 complete docs**: `tests/PHASE2-COMPLETE.md`
- **Testing strategy**: `tests/TODO.md`

---

## Quick Reference

| Task | Command |
|------|---------|
| Run all tests with coverage | `pytest` |
| Run fast (no coverage) | `pytest --no-cov -q` |
| Run single action tests | `pytest .github/actions/scanner-x/tests/` |
| Run single test file | `pytest .github/actions/scanner-x/tests/test_parse_results.py -v` |
| Run specific test | `pytest .github/actions/scanner-x/tests/test_parse_results.py::test_parse_counts -v` |
| Validate actions | `pytest tests/unit/actions/` |
| See coverage report | `pytest --cov --cov-report=html` (open htmlcov/index.html) |

**Test fast, test often, ship with confidence!** 🚀
