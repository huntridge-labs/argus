<div align="center">

<img src="https://raw.githubusercontent.com/huntridge-labs/argus/main/img/argus_readme_cover.png" alt="Argus — Perception is Protection" width="600">

**Unified security scanning — SAST, containers, IaC, secrets, dependencies, and DAST from a single CLI.**

</div>

## Install

```bash
pip install argus-security
```

## Quick Start

```bash
argus init        # Create argus.yml config
argus scan        # Run all configured scanners
```

Or scan immediately without a config file:

```bash
argus scan bandit gitleaks osv --severity-threshold high
```

## Features

- **14+ security scanners** -- SAST, secrets, containers, IaC, dependencies, DAST, supply chain, malware
- **Single CLI** -- `argus scan` runs everything, locally or in CI
- **Flexible selection** -- run all scanners, specific ones, or groups
- **Multiple output formats** -- terminal, Markdown, SARIF, JSON
- **Severity thresholds** -- fail builds on `low`, `medium`, `high`, or `critical`
- **Docker-backed execution** -- scanners run in containers when not installed locally
- **Config-driven** -- `argus.yml` for repeatable scan profiles
- **GitHub Actions integration** -- composite actions for native CI/CD workflows
- **Linting built in** -- YAML, JSON, Python, JavaScript, Dockerfile, Terraform

## Supported Scanners

| Category | Scanners |
|----------|----------|
| SAST | Bandit, OpenGrep, CodeQL |
| Secrets | Gitleaks |
| Containers | Trivy, Grype, Syft |
| IaC | Trivy IaC, Checkov |
| Dependencies | OSV Scanner |
| Supply Chain | zizmor + actionlint |
| Malware | ClamAV |
| DAST | ZAP |
| Compliance | FedRAMP SCN Detector |

## Configuration

```yaml
# argus.yml
scanners:
  - gitleaks
  - bandit
  - osv
  - trivy-iac

scan_path: "."
severity_threshold: high
```

## MCP Server (AI Integration)

Argus includes an MCP server so AI assistants (Claude, Copilot, Cursor) can run scans, validate configs, and detect project characteristics directly.

```bash
pip install argus-security[mcp]
```

Add to your AI tool's MCP configuration:

```json
{
  "mcpServers": {
    "argus": {"command": "argus", "args": ["mcp"]}
  }
}
```

Available tools: `argus_scan`, `argus_detect`, `argus_validate`, `argus_list_scanners`, `argus_init`

## Documentation

- **Full docs:** [huntridge-labs.github.io/argus](https://huntridge-labs.github.io/argus/)
- **GitHub:** [github.com/huntridge-labs/argus](https://github.com/huntridge-labs/argus)
- **Configuration reference:** [docs/config-reference.md](https://github.com/huntridge-labs/argus/blob/main/docs/config-reference.md)
- **Scanner reference:** [docs/scanners.md](https://github.com/huntridge-labs/argus/blob/main/docs/scanners.md)
- **Examples:** [examples/](https://github.com/huntridge-labs/argus/tree/main/examples)
- **Contributing:** [CONTRIBUTING.md](https://github.com/huntridge-labs/argus/blob/main/CONTRIBUTING.md)

## License

AGPL-3.0 -- see [LICENSE.md](https://github.com/huntridge-labs/argus/blob/main/LICENSE.md) for details.
