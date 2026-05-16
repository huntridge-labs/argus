# Argus TestPyPI Validation Guide

Use this prompt with Claude Code to thoroughly test the latest Argus pre-release from TestPyPI.

## Prerequisites

- Python 3.11+ installed
- Docker Desktop running
- Claude Code CLI installed

## Claude Prompt

Copy and paste this into Claude Code:

---

```
Test the latest argus-security pre-release from TestPyPI. Run every test in an isolated environment — do not modify any existing project files.

Prerequisites check:
1. Verify Python 3.11+ is available
2. Verify Docker is running

Setup:
1. Create a temp directory and venv
2. pip install from TestPyPI: pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ argus-security
3. Verify: argus --version

Create test files with intentional vulnerabilities:
- Python file with: subprocess shell=True, hardcoded passwords, weak MD5 hash, insecure random
- A file with a fake AWS secret key (AKIA...)
- A Dockerfile with: FROM ubuntu:latest, USER root, RUN chmod 777, EXPOSE 22
- An invalid JSON file with trailing commas
- A YAML file with intentional formatting issues
- Init a git repo in the test dir (gitleaks needs git history)

Test each feature:

1. argus --version — verify it prints a version
2. argus scan --list — verify all 16 scanners show with availability status
3. argus init — verify it detects the project and generates argus.yml
4. argus validate — verify the generated config is valid
5. argus scan bandit --path . --format json --format markdown --output-dir ./results --output-vars ./results/counts.env --no-timestamp --severity-threshold none — verify it pulls the Docker container from GHCR and finds the planted vulnerabilities
6. argus scan gitleaks --path . --format json --output-dir ./results-gitleaks --no-timestamp --severity-threshold none — verify it detects the AWS key
7. argus scan lint-json --path . --no-timestamp --severity-threshold none — verify it catches invalid JSON
8. argus scan lint-yaml --path . --no-timestamp --severity-threshold none — verify it catches YAML issues
9. argus scan opengrep --path . --format json --output-dir ./results-opengrep --no-timestamp --severity-threshold none — verify it runs via Docker
10. argus completion zsh — verify it generates completion script
11. argus classify --help — verify the SCN subcommand exists

For each test, report:
- Whether it passed or failed
- What Docker images were pulled (if any)
- Number of findings
- Any errors or warnings

Validate the outputs:
- Check results/counts.env has critical_count, high_count, medium_count, low_count, total_count, passed keys
- Check results/argus-summary.md contains a markdown table with findings
- Check results/argus-results.json has valid JSON with results array
- Check results/argus-results.sarif has version 2.1.0

Clean up the temp directory when done.

Report a summary table of all test results.
```

---

## Expected Results

| Test | Expected |
|------|----------|
| `--version` | `0.7.0.devXXX` |
| `--list` | 16 scanners with local/container/not-found status |
| `init` | Detects Python + Docker, generates argus.yml |
| `validate` | Config valid, shows enabled scanners |
| `scan bandit` | Pulls `scanner-bandit:0.7.0` from GHCR, finds 5+ vulnerabilities |
| `scan gitleaks` | Pulls `gitleaks:v8.30.1` from Docker Hub, finds AWS key |
| `scan lint-json` | Uses Python fallback, finds invalid JSON |
| `scan lint-yaml` | Uses local yamllint or reports unavailable |
| `scan opengrep` | Pulls `scanner-opengrep:0.7.0` from GHCR |
| `completion zsh` | Outputs valid zsh completion script |
| `classify --help` | Shows SCN classification options |
| `counts.env` | All expected keys present |
| `argus-summary.md` | Markdown table with severity breakdown |
| `argus-results.json` | Valid JSON with results array |
| `argus-results.sarif` | SARIF 2.1.0 format |

## Reporting Issues

If any test fails, report:
1. OS and architecture (Intel Mac, Apple Silicon, Linux)
2. Python version
3. Docker version
4. The full error output
5. Whether the Docker image pulled successfully
