# Tests

Comprehensive testing suite for argus composite actions and supporting scripts.

## Overview

This testing infrastructure validates all components of the argus project:

- **174+ tests** across multiple languages (Bash, JavaScript, Python)
- **Co-located tests** - tests live alongside the actions they validate
- **Shared fixtures** - mock data in `tests/fixtures/` reused across tests
- **Zero vulnerable code** - all tests use synthetic fixtures
- **Automated CI/CD** - tests run on every PR
- **Fast feedback** - unit tests complete in <30 seconds

## Test Structure

```
.github/actions/
├── scanner-*/
│   ├── action.yml         # Action definition
│   ├── scripts/           # Action scripts (parsers, generators)
│   └── tests/             # Co-located tests for this action
│       ├── test-*.sh      # Bash tests
│       ├── test-*.test.js # JavaScript tests
│       └── test_*.py      # Python tests
├── parse-*/
│   ├── action.yml
│   ├── scripts/
│   └── tests/
└── ...

tests/
├── fixtures/              # Shared test data (no real vulnerabilities)
│   ├── scanner-outputs/   # Mock scanner results (Bandit, Trivy, ZAP, etc.)
│   ├── test-apps/         # Minimal test applications
│   └── configs/           # Test configuration files
├── unit/actions/          # Action schema validation tests
├── CONTRIBUTING.md        # Detailed testing guide
└── TODO.md                # Testing roadmap and status
```

**Key Design**: Tests are co-located with the actions they test, but share fixtures from `tests/fixtures/` since multiple actions use the same mock data.

## Quick Start

```bash
# Install dependencies
npm install
pip install -r .devcontainer/requirements.txt

# Run all tests
npm test

# Run specific test suites
npm run test:bash      # Bash parser & summary tests
npm run test:js        # JavaScript config parsers
npm run test:python    # Python utilities
npm run test:actions   # Action schema validation

# Fast validation only (<1s)
npm run validate
```

## Test Coverage

| Category | Tests | Location | Purpose |
|----------|-------|----------|----------|
| **Bash Script Tests** | 54 | `.github/actions/*/tests/` | Parser scripts, summary generators |
| **JavaScript Tests** | 60 | `.github/actions/parse-*/tests/` | Config parsers |
| **Python Tests** | 8 | `.github/actions/scanner-clamav/tests/` | Python utilities |
| **Schema Validation** | 52 | `tests/unit/actions/` | Composite action metadata |
| **Integration Tests** | 16+ jobs | `.github/workflows/test-actions*.yml` | End-to-end workflows |
| **Total** | **174+** | - | Complete validation of all components |

## CI/CD Integration

Tests run automatically via GitHub Actions:

- **`test-unit.yml`** - Runs on all PRs (unit tests + coverage)
- **`test-actions.yml`** - Runs on action changes (integration tests)
- **Path-based triggers** - Only affected components tested
- **Non-blocking** - Tests provide feedback but don't block PRs

## Adding Tests

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidance on:

- When to add unit vs integration tests
- Test patterns and templates
- Updating fixtures
- Common pitfalls

## Key Design Principles

1. **No Real Vulnerabilities** - All tests use synthetic fixtures from `fixtures/scanner-outputs/`
2. **Fast Feedback** - Unit tests run in seconds, integration tests in minutes
3. **Clear Failures** - Descriptive test names and error messages
4. **Easy Contribution** - Templates and examples for new tests

## More Information

- **Fixtures**: See [fixtures/README.md](fixtures/README.md) for test data structure
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guide
- **Status**: See [TODO.md](TODO.md) for implementation roadmap

---

**Current Status**: All 5 phases complete! 🎉 Tests co-located with actions, shared fixtures, 174+ tests validating every change.
