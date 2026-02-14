# Test Fixtures

This directory contains synthetic test data for testing the hardening-workflows composite actions and scripts **without real vulnerabilities in the codebase**.

## Purpose

The fixtures eliminate the need for actual vulnerable code by providing:
- Pre-generated scanner outputs with known findings
- Simple test applications (no real vulnerabilities)
- Test configurations for workflows
- SARIF format examples

## Directory Structure

```
fixtures/
├── scanner-outputs/      # Pre-captured scanner results (JSON, SARIF, text)
│   ├── bandit/          # Bandit Python security scanner outputs
│   ├── codeql/          # CodeQL SARIF outputs
│   ├── checkov/         # Checkov IaC scanner outputs
│   ├── trivy/           # Trivy container scanner outputs
│   ├── zap/             # OWASP ZAP web scanner outputs
│   ├── gitleaks/        # Gitleaks secret scanner outputs
│   └── clamav/          # ClamAV malware scanner outputs
├── test-apps/           # Minimal test applications (secure code)
│   ├── python-app/      # Flask app for testing
│   └── node-app/        # Express app for testing
├── configs/             # Test configuration files
│   ├── container-config.yml
│   ├── zap-config.yml
│   ├── invalid-*.yml    # For negative testing
│   └── docker-compose.test.yml
└── sarif-samples/       # Additional SARIF format examples
```

## Scanner Output Files

### Bandit (Python Security)

- **results-zero-findings.json** - Clean scan with no issues
- **results-with-findings.json** - 6 findings (2 HIGH, 3 MEDIUM, 1 LOW)
  - Tests: pickle usage, exec, hardcoded password, os.system, tmp directory, assert

### CodeQL (Multi-language)

- **results-zero-findings.sarif** - Clean SARIF scan
- **results-with-findings.sarif** - 3 findings
  - SQL injection (HIGH)
  - Path injection (HIGH)
  - Clear-text logging (MEDIUM)

### Checkov (IaC Security)

- **results-zero-findings.json** - All checks passed
- **results-with-findings.json** - 5 failed checks (2 HIGH, 2 MEDIUM, 1 LOW)
  - IMDSv1 enabled, S3 encryption missing, S3 versioning missing, CloudWatch encryption, S3 public access blocks

### Trivy (Container Security)

- **results-zero-findings.json** - Clean Alpine image
- **results-with-findings.json** - 4 CVEs (1 CRITICAL, 1 HIGH, 1 MEDIUM, 1 LOW)
  - CVE-2023-1234 (libssl), CVE-2023-5678 (curl), CVE-2023-9012 (libc6), CVE-2024-0001 (bash)

### ZAP (Web Application)

- **results-zero-findings.json** - Clean scan
- **results-baseline-scan.json** - 3 findings (2 LOW, 1 MEDIUM)
  - X-Content-Type-Options missing, Cookie SameSite missing, CORS misconfiguration

### Gitleaks (Secrets)

- **results-zero-findings.json** - No secrets found
- **results-with-findings.json** - 3 secrets detected
  - GitHub PAT, AWS Access Key, Generic API Key

### ClamAV (Malware)

- **results-clean.txt** - No malware detected
- **results-with-findings.txt** - 2 malware files found

## Test Applications

### Python App (`test-apps/python-app/`)

Minimal Flask application with:
- Basic REST endpoints (/, /health, /api/data, /api/echo)
- No real vulnerabilities
- Used for testing Bandit, CodeQL, and container scanners

**Files:**
- `app.py` - Main Flask application
- `requirements.txt` - Dependencies (Flask, Werkzeug)
- `README.md` - Usage instructions

### Node.js App (`test-apps/node-app/`)

Minimal Express application with:
- Security headers (Helmet.js)
- Rate limiting
- Basic REST endpoints
- No real vulnerabilities
- Dockerfile included

**Files:**
- `server.js` - Main Express application
- `package.json` - Dependencies (Express, Helmet, rate-limit)
- `Dockerfile` - Multi-stage secure build
- `README.md` - Usage instructions

## Configuration Files

### container-config.yml

Comprehensive container scanning configuration demonstrating:
- Multiple image sources (Dockerfile builds and registry pulls)
- Scanner selection per image
- Registry authentication
- Build arguments
- Global scanner configuration

### zap-config.yml

ZAP scanning configuration with all modes:
- **URL mode** - Baseline and full scans
- **Docker-run mode** - API scan with OpenAPI spec
- **Compose mode** - Baseline scan with docker-compose
- Readiness checks
- Global ZAP settings

### Invalid Configs

- **invalid-container-config.yml** - Missing required fields, invalid scanners
- **invalid-zap-config.yml** - Missing fields, invalid modes

### Supporting Files

- **docker-compose.test.yml** - Multi-service test stack (web + db)
- **openapi.yaml** - OpenAPI 3.0 spec for API testing

## Usage in Tests

### Unit Tests (Scripts)

Test parser scripts against synthetic outputs:

```bash
# Test Bandit parser
./.github/scripts/parse-bandit-results.sh counts \
  tests/fixtures/scanner-outputs/bandit/results-with-findings.json
# Expected: "2 3 1"

# Test Trivy parser
./.github/scripts/parse-trivy-results.sh counts \
  tests/fixtures/scanner-outputs/trivy/results-with-findings.json
# Expected: "1 1 1 1"
```

### Integration Tests (Actions)

Use fixtures in GitHub Actions workflows:

```yaml
- name: Test Bandit Scanner
  uses: ./.github/actions/scanner-bandit
  with:
    python_path: tests/fixtures/test-apps/python-app

- name: Test Container Scanner
  uses: ./.github/actions/scanner-container
  with:
    config_file: tests/fixtures/configs/container-config.yml
```

### Config Parser Tests

Validate configuration parsers:

```bash
# Test valid config
node .github/scripts/parse-container-config.js \
  tests/fixtures/configs/container-config.yml

# Test invalid config (should fail)
node .github/scripts/parse-container-config.js \
  tests/fixtures/configs/invalid-container-config.yml
```

## Generating New Fixtures

### Adding New Scanner Outputs

1. Run actual scanner on clean code
2. Capture JSON/SARIF output
3. **Remove any real vulnerability data**
4. Add synthetic findings if needed
5. Save to appropriate `scanner-outputs/` subdirectory
6. Create both zero-findings and with-findings variants

Example for a new scanner:

```bash
# Run scanner and capture output
bandit -r tests/fixtures/test-apps/python-app -f json -o temp-output.json

# Review and sanitize
# Add to scanner-outputs/bandit/
mv temp-output.json tests/fixtures/scanner-outputs/bandit/results-custom.json
```

### Modifying Test Apps

Test applications should remain **simple and secure**:
- No hardcoded secrets
- No real vulnerabilities
- Minimal dependencies
- Clear documentation

Update apps only when:
- Testing new scanner features
- Adding new language support
- Improving test coverage

### Schema Validation

Always validate config files against schemas:

```bash
# Container config
ajv validate -s .github/schemas/container-config.schema.json \
  -d tests/fixtures/configs/container-config.yml

# ZAP config
ajv validate -s .github/schemas/zap-config.schema.json \
  -d tests/fixtures/configs/zap-config.yml
```

## Maintenance

### When to Update Fixtures

- Scanner output format changes
- New severity levels or fields added
- Schema updates
- Adding test coverage for new features

### Fixture Versioning

Document scanner versions used:
- Bandit: 1.7.5+
- CodeQL: 2.15.4+
- Checkov: 3.1.25+
- Trivy: 0.48.0+
- ZAP: 2.14.0+
- Gitleaks: 8.18.0+
- ClamAV: 1.3.0+

### Validation Checklist

Before committing new fixtures:
- [ ] No real secrets or credentials
- [ ] No actual vulnerable code
- [ ] Parser scripts handle the format
- [ ] Both positive and negative cases covered
- [ ] Documentation updated
- [ ] Passes schema validation (if applicable)

## Benefits of This Approach

✅ **No Security Alerts** - GitHub Advanced Security won't flag test files
✅ **Predictable Tests** - Exact control over test scenarios
✅ **Fast Execution** - No actual scanning during tests
✅ **Easy Maintenance** - Update fixtures independently of code
✅ **Clear Intent** - Obvious these are test files, not real vulnerabilities

## See Also

- [Testing Strategy](../TODO.md) - Overall testing architecture
- [Contributing Guide](../../CONTRIBUTING.md) - How to add tests
- [Scripts Documentation](../../.github/scripts/README.md) - Parser script usage
