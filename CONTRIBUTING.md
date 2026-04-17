# Contributing to Argus

Welcome! This guide covers how to contribute composite actions to the security scanning toolkit.

> **Architecture Note**: This project uses an actions-first architecture where scanner logic lives in composite actions (`.github/actions/`). The reusable workflows (`.github/workflows/`) are thin wrappers maintained for backwards compatibility on github.com.

## Table of Contents

- [Getting Started](#getting-started)
- [Adding a New Scanner Action](#adding-a-new-scanner-action)
- [Testing Your Changes](#testing-your-changes)
- [Documentation Requirements](#documentation-requirements)
- [Pull Request Process](#pull-request-process)
- [Best Practices](#best-practices)

---

## Getting Started

### Prerequisites

- Git
- GitHub account
- Basic understanding of GitHub Actions
- Familiarity with bash scripting (for parser scripts)
- Knowledge of the scanner tool you're integrating

### Project Structure

```
.github/actions/
├── scanner-*/                    # Scanner composite actions
│   ├── action.yml               # Action definition
│   ├── .docsite.yml             # Docsite category declaration
│   ├── README.md                # Action documentation
│   ├── scripts/                 # Bundled Python scripts
│   │   ├── parse-results.py     # Parse scanner output → JSON
│   │   └── generate-summary.py  # Generate markdown summary
│   └── tests/                   # Co-located pytest tests
│       ├── test_parse_results.py
│       ├── test_generate_summary.py
│       └── conftest.py (optional)
├── linter-*/                    # Linter composite actions
├── parse-container-config/      # Config parser actions
├── security-summary/            # Summary aggregators
└── README.md                    # Actions catalog

examples/
├── workflows/
│   ├── composite-actions-example.yml     # Complete security workflow
│   └── actions-linting-example.yml       # Complete linting workflow
└── README.md

tests/
├── fixtures/                    # Shared mock data and test apps
└── unit/actions/                # Action schema validation
```

### Key Concepts

**Composite Actions** vs **Reusable Workflows**:
- ✅ Self-contained with bundled scripts
- ✅ Works on GHES with github.com access
- ✅ Easier to compose and test
- ✅ No cross-repo workflow call overhead

---

## Adding a New Scanner Action

### Step 1: Create Action Structure

Create the directory structure for your scanner:

```bash
mkdir -p .github/actions/scanner-example/scripts
touch .github/actions/scanner-example/action.yml
touch .github/actions/scanner-example/.docsite.yml
touch .github/actions/scanner-example/README.md
touch .github/actions/scanner-example/scripts/parse-results.py
touch .github/actions/scanner-example/scripts/generate-summary.py
```

### Step 2: Define action.yml

See existing scanner actions for reference patterns (e.g., `scanner-bandit/action.yml`, `scanner-checkov/action.yml`).

**Standard structure**:
```yaml
name: 'Example Scanner'
description: |
  Run Example security scanner and generate reports.

inputs:
  scan_path:                  # What to scan
  fail_on_severity:          # Threshold (none/low/medium/high/critical)
  enable_code_security:      # Upload SARIF boolean
  post_pr_comment:          # Post PR comment boolean
  job_id:                   # For artifact naming

outputs:
  critical_count:           # Number of findings by severity
  high_count:
  medium_count:
  low_count:
  total_count:
  scan_status:             # passed/failed/skipped

runs:
  using: 'composite'
  steps:
    - name: Validate inputs
    - name: Run scanner
    - name: Parse results (using scripts/parse-results.sh)
    - name: Upload SARIF (if enabled)
    - name: Upload reports artifact
    - name: Generate summary (using scripts/generate-summary.sh)
    - name: Upload summary artifact
    - name: Comment PR (if enabled)
```

**Key patterns to follow**:
- Use `${{ github.action_path }}/scripts/` to reference bundled scripts
- Set `if: always()` on result processing steps
- Use `continue-on-error: true` for optional steps (SARIF, PR comments)
- Follow naming conventions for artifacts: `{scanner}-reports-{job_id}`

### Step 3: Create Parser Script

Create `scripts/parse-results.py`:

```python
#!/usr/bin/env python3
"""
Example Scanner Results Parser
Usage: parse-results.py counts <report_file>
"""

import json
import sys
from pathlib import Path

def parse_counts(report_file):
    """Extract severity counts from scanner report."""
    if report_file == '-':
        data = json.load(sys.stdin)
    else:
        try:
            with open(report_file) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return 0, 0, 0, 0

    # Adjust parsing logic for your scanner's output format
    critical = len([r for r in data.get('results', []) if r.get('severity') == 'CRITICAL'])
    high = len([r for r in data.get('results', []) if r.get('severity') == 'HIGH'])
    medium = len([r for r in data.get('results', []) if r.get('severity') == 'MEDIUM'])
    low = len([r for r in data.get('results', []) if r.get('severity') == 'LOW'])

    return critical, high, medium, low

if __name__ == '__main__':
    command = sys.argv[1] if len(sys.argv) > 1 else None
    report_file = sys.argv[2] if len(sys.argv) > 2 else None

    if command == 'counts':
        c, h, m, l = parse_counts(report_file)
        print(f"{c} {h} {m} {l}")
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)
```

**Parser requirements**:
- Must handle missing files gracefully (return 0 counts)
- Must handle malformed JSON (catch exceptions)
- Must map scanner's severity levels to standard: CRITICAL, HIGH, MEDIUM, LOW
- Output format: space-separated counts for environment variable assignment
- Support reading from stdin with `-` argument

### Step 4: Create Summary Generator

Create `scripts/generate-summary.py`:

```python
#!/usr/bin/env python3
"""
Example Scanner Summary Generator
Usage: generate-summary.py <output_file> <is_pr_comment>
"""

import os
import sys
from pathlib import Path

def generate_summary(output_file, is_pr_comment=False):
    """Generate markdown summary from severity counts."""

    # Get counts from environment
    critical = os.environ.get('CRITICAL', '0')
    high = os.environ.get('HIGH', '0')
    medium = os.environ.get('MEDIUM', '0')
    low = os.environ.get('LOW', '0')
    total = os.environ.get('TOTAL', '0')

    lines = []

    if is_pr_comment:
        lines.append('<details>')
        lines.append('<summary>🔍 Example Scanner</summary>')
    else:
        lines.append('## 🔍 Example Scanner Results')

    lines.append('')
    lines.append('| 🚨 Critical | ⚠️ High | 🟡 Medium | 🔵 Low | ❌ Total |')
    lines.append('|-------------|---------|-----------|--------|----------|')
    lines.append(f'| **{critical}** | **{high}** | **{medium}** | **{low}** | **{total}** |')
    lines.append('')

    # Add artifacts link
    github_url = os.environ.get('GITHUB_SERVER_URL', 'https://github.com')
    repo = os.environ.get('GITHUB_REPOSITORY', '')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    artifacts_url = f"{github_url}/{repo}/actions/runs/{run_id}#artifacts"
    lines.append(f'**📁 Artifacts:** [View Reports]({artifacts_url})')

    if is_pr_comment:
        lines.append('</details>')

    # Write to file
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        f.write('\n'.join(lines) + '\n')

if __name__ == '__main__':
    output_file = sys.argv[1] if len(sys.argv) > 1 else 'scanner-summaries/example.md'
    is_pr_comment = sys.argv[2].lower() == 'true' if len(sys.argv) > 2 else False
    generate_summary(output_file, is_pr_comment)
```

**Summary requirements**:
- Use consistent emoji and formatting
- Support both PR comment and job summary modes
- Include artifacts link
- Keep it concise but informative
- Create output directory if it doesn't exist

### Step 5: Create Documentation

Create `README.md` for your action:

```markdown
# Example Scanner Composite Action

Brief description of what this scanner detects.

## Usage

### Basic Example
\`\`\`yaml
- uses: huntridge-labs/argus/.github/actions/scanner-example@0.7.2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_path: 'src'
    fail_on_severity: 'high'
\`\`\`

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `scan_path` | Path to scan | No | `.` |
| `fail_on_severity` | Fail threshold | No | `none` |
| `enable_code_security` | Upload SARIF | No | `false` |
| `post_pr_comment` | Post PR comment | No | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `critical_count` | Critical findings |
| `high_count` | High findings |
| `total_count` | Total findings |
| `scan_status` | Status (passed/failed/skipped) |

## Requirements

- Scanner tool version requirements
- Supported file types
- Dependencies
```

### Step 6: Register with the Documentation Site

Create `.github/actions/scanner-example/.docsite.yml` to declare the action's category:

```yaml
category: sast  # Must match a category defined in docsite.yml
```

Available categories are defined in `docsite.yml` at the repo root (e.g., `sast`, `secrets`, `container`, `dast`, `infrastructure`, `malware`, `dependencies`, `linting`, `compliance`, `ai`, `utility`).

To validate your configuration:

```bash
cd scripts && python -m docsite --validate
```

This ensures your `.docsite.yml` exists, references a valid category, and that the site will build correctly.

To preview the documentation site locally:

```bash
cd scripts && python -m docsite --output-dir /tmp/argus-docs
cd /tmp/argus-docs && mkdocs serve
```

### Step 7: Update Actions Catalog

Add to `.github/actions/README.md`:

```markdown
| [scanner-example](scanner-example/) | Example scanner description | Languages | [README](scanner-example/README.md) |
```

### Step 8: Add to Example Workflows

Add your scanner to `examples/workflows/composite-actions-example.yml`:

```yaml
  example-scanner:
    name: Example Scanner
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/scanner-example@0.7.2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          scan_path: 'src'
          post_pr_comment: false  # Let security-summary handle comments

  security-summary:
    needs:
      - example-scanner  # Add to needs array
      - bandit
      # ... other scanners
```

---

## Testing Your Changes

### Testing Approach

**Co-located tests** - pytest tests live with the actions they validate:
```
.github/actions/scanner-myScanner/
├── action.yml
├── scripts/
│   ├── parse-results.py
│   └── generate-summary.py
└── tests/                      # ← Tests co-located here
    ├── test_parse_results.py
    ├── test_generate_summary.py
    └── conftest.py (optional)
```

**Shared fixtures** - mock data centralized for reuse:
```
tests/fixtures/
├── scanner-outputs/            # Mock scanner results
├── test-apps/                  # Minimal test apps
└── configs/                    # Test configurations
```

**Run tests**:
```bash
pytest                          # All tests with coverage
pytest --no-cov -q              # Fast mode (no coverage)
pytest .github/actions/scanner-x/tests/  # Single action tests
```

**Key principles**:
1. Tests co-located with actions they test
2. Fixtures shared across actions (avoid duplication)
3. Use synthetic data, not real vulnerabilities
4. Measure coverage with pytest-cov

See `tests/CONTRIBUTING.md` for detailed pytest guide.

### Manual Testing

Create a test workflow:

```yaml
name: Test Example Scanner

on:
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: ./.github/actions/scanner-example
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          scan_path: 'tests/fixtures/test-apps/example-app'
```

### Automated Testing ✅

Test infrastructure is complete:

- ✅ Unit tests for parser scripts (co-located in `.github/actions/*/tests/`)
- ✅ Unit tests for summary generators (co-located)
- ✅ Integration tests for full actions (`.github/workflows/test-actions*.yml`)
- ✅ Coverage reporting via Codecov
- ✅ 174+ tests running in CI/CD

### Validation Checklist

- [ ] Action runs without errors
- [ ] All outputs are set correctly
- [ ] Parser handles various input formats
- [ ] Summary markdown is valid
- [ ] `.docsite.yml` created with valid category
- [ ] Docsite validation passes: `cd scripts && python -m docsite --validate`
- [ ] Unit tests added in `.github/actions/*/tests/`
- [ ] Tests use shared fixtures from `tests/fixtures/`
- [ ] All tests pass: `pytest`
- [ ] SARIF upload works (if applicable)
- [ ] Artifacts upload with correct names
- [ ] PR comments work
- [ ] Severity thresholds fail appropriately

---

## Documentation Requirements

Every scanner action must include:

1. **Action README.md**
   - Purpose and capabilities
   - Usage examples
   - Complete inputs/outputs tables
   - Requirements

2. **Docsite Registration**
   - `.docsite.yml` with valid category (see Step 6 above)
   - Validate with `cd scripts && python -m docsite --validate`

3. **Inline Documentation**
   - Comments in action.yml
   - Comments in scripts
   - Helpful error messages

4. **Catalog Entry**
   - Add to `.github/actions/README.md`

5. **Usage Example**
   - Add to `examples/composite-actions-example.yml`

6. **Changelog**
   - Update `CHANGELOG.md`

---

## Pull Request Process

### Before Submitting

- [ ] Manual testing complete
- [ ] Documentation complete
- [ ] Unit tests added in `.github/actions/*/tests/`
- [ ] All tests pass: `pytest`
- [ ] Coverage meets 80% threshold
- [ ] Follows existing patterns
- [ ] Automated tests pass in CI

### PR Template

```markdown
## Add Example Scanner Composite Action

### Summary
Brief description of the scanner.

### Scanner Details
- **Tool**: Example Scanner v1.0
- **Languages**: Python, JavaScript
- **Output Formats**: SARIF, JSON

### Changes
- ✅ Created scanner-example action
- ✅ Added parser and summary scripts
- ✅ Updated actions catalog
- ✅ Added examples
- ✅ Documentation complete

### Testing
- [x] Tested manually
- [x] Verified outputs
- [x] Confirmed artifacts
- [ ] TODO: Unit tests
- [ ] TODO: Integration tests

### Usage
\`\`\`yaml
- uses: huntridge-labs/argus/.github/actions/scanner-example@0.7.2
\`\`\`
```

---

## Best Practices

### Naming Conventions

- **Actions**: `scanner-{tool}` or `linter-{tool}`
- **Scripts**: `parse_results.py`, `generate_summary.py`
- **Artifacts**: `{tool}-reports-{job_id}`, `scanner-summary-{tool}-{job_id}`

### Script Guidelines

1. Validate inputs before processing
2. Handle missing files gracefully
3. Provide default values
4. Use descriptive error messages
5. Use `pathlib` for file operations

### Security

- Never hardcode secrets
- Validate all inputs
- Use `continue-on-error` for optional steps
- Pin action versions
- Minimize required permissions

### Performance

- Set reasonable timeouts
- Cache dependencies
- Minimize scan scope
- Generate only necessary formats

---

## Migration Complete ✅

All action scripts and tests are now Python with pytest:
- ✅ All scripts converted to Python (`*.py`)
- ✅ All tests migrated to pytest
- ✅ Unified coverage with pytest-cov
- ✅ Duplicate scripts eliminated (container-summary, zap-summary)

---

## Getting Help

- 📋 Check existing actions for patterns
- 📖 Review `CLAUDE.md` for architecture
- 📝 See `tests/TODO.md` for testing
- 💬 Open a [Discussion](https://github.com/huntridge-labs/argus/discussions)
- 🐛 Report via [Issues](https://github.com/huntridge-labs/argus/issues)

---

**Thank you for contributing! 🎉**
