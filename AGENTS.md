# AGENTS.md

> The entry point for every coding agent in this repo (Claude Code, GitHub Copilot, Cursor, Codex and the rest), and a short orientation for people. `CLAUDE.md` imports this file and `.github/copilot-instructions.md` is a symlink to it. It holds only what you can't get from the code: the rules, the invariants and the reasons. For what exists and how it fits together, read the code or follow the [routing table](#where-to-look).

**argus** is Huntridge Labs' security scanning framework: a Python SDK and CLI (`argus scan`, package `argus-security`) plus composite GitHub Actions under `.github/actions/`. The SDK is the primary interface. Composite actions are for GitHub Actions users, including GitHub Enterprise Server with github.com access.

- **Current version**: 1.15.0
- **License**: AGPL-3.0

**Quick reference:** every change starts with a GitHub issue, one PR per issue. Branch `<prefix>/<issue>-<description>` (for example `feat/483-issue-keyed-records`), open a draft PR as soon as work starts, and record a new ADR as `.ai/decisions/ADR-<issue>.yaml`. Details in [Issues, branches, and records](#issues-branches-and-records).

## Principles

1. **Trust is everything.** Dependency updates (Dependabot, Renovate) arrive as PRs, the pipeline tests them, and green means trusted enough to merge and release. Tests have to be robust enough to earn that.
2. **Keep code simple.** Easy for anyone to understand and extend.
3. **Docs say what code can't.** Don't hand-write lists or counts of things the code already knows (scanners, modules, tests). Point at the registry or generate it.

## Issues, branches, and records

These rules apply to people and coding agents alike. An issue number is unique, so anything keyed to it (a branch, a PR, an ADR) can't clash with another PR's, and parallel work stops colliding. The reasoning is in [ADR-483](.ai/decisions/ADR-483.yaml).

### Before you start

1. **Start from an issue.** Every change has a GitHub issue, and each PR covers one issue. Split big work into sub-issues and give each its own PR. No issue yet? Open one first.
2. **Name the branch after the issue.** `<prefix>/<issue>-<short-description>`, for example `feat/483-issue-keyed-records`. Use the sub-issue's number, never the parent's or the epic's. A ruleset rejects other prefixes; use one of `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `test`, `ci`, `build`, `revert` or `hotfix`. (`copilot/`, `claude/`, `dependabot/`, `renovate/` and `aicac/` are allowed only for tools that pick their own branch names.)
3. **Check nobody has it, then open a draft PR.** If a linked open PR or a branch named for the issue exists, stop and ask on the issue.
   ```bash
   gh issue view <issue> --json closedByPullRequestsReferences --jq '.closedByPullRequestsReferences[].url'
   gh pr list --state open --search "<issue>"
   git ls-remote --heads origin "*/<issue>-*"
   ```
   If all come back empty, push your first commit and open a draft PR (`gh pr create --draft`) so everyone can see the issue is taken.
4. **Link the issue.** Put `Closes #<issue>` in the PR body when the PR finishes the issue, or `Refs #<issue>` when it's partial work. The PR template has the line.
5. **Record decisions under the issue number.** A new ADR is one file, `.ai/decisions/ADR-<issue>.yaml`, created with `python -m scripts.ci.adr_records new --title "..."`. Never add entries to `.ai/decisions.yaml` (closed at ADR-044) and never renumber an ADR. One ADR per PR: a PR with two decisions records both in its one ADR or gets split into two issues.
6. **Never rename a PR's head branch on GitHub.** It closes the PR. Push a new, correctly named branch and open a new PR instead.

Nobody edits an ADR index by hand: `python -m scripts.ci.adr_records list` builds it from both stores, and the **ADR Records** workflow checks every PR. The ADR fields, the check's error messages and their fixes, and how to move a PR to a new branch are in [`docs/developer/adr-records.md`](docs/developer/adr-records.md).

## Where to look

Read what the task needs, not everything. The `.ai/` files are large (`decisions.yaml` alone is ~50k tokens), so search them rather than loading them whole.

| To... | Read |
|---|---|
| Add an SDK scanner | [`CONTRIBUTING.md`, "Adding a Scanner via the SDK"](CONTRIBUTING.md#adding-a-scanner-via-the-sdk), `argus/core/scanner.py` (the protocol), `argus/core/scanner_template.py`, the registry in `argus/scanners/__init__.py`. Then do the [secret-leak audit](#secret-leak-audit). |
| Add a linter | [`CONTRIBUTING.md`, "Adding a Linter via the SDK"](CONTRIBUTING.md#adding-a-linter-via-the-sdk), `argus/core/linter_template.py`, `argus/linters/yamllint.py` |
| Add a reporter | [`docs/contributing-reporters.md`](docs/contributing-reporters.md) |
| Add or change a composite action | [`CONTRIBUTING.md`, "Adding a Composite Action"](CONTRIBUTING.md#adding-a-composite-action-github-actions); `scanner-clamav` is the reference. Check the [composite-only boundary](#invariants) first. |
| Change `argus.yml` options | [`docs/config-reference.md`](docs/config-reference.md), `argus/core/config.py`, `argus/core/schema.py` |
| Change the CLI | `argus/cli.py`, then `python -m scripts.ci.check_cli_docs --fix` to regenerate `docs/cli-reference.md` |
| Work on the SCN detector | `argus/scn/` (`argus classify`) and [`.github/actions/scn-detector/README.md`](.github/actions/scn-detector/README.md), which also has its design notes |
| Write or fix tests | [`tests/CONTRIBUTING.md`](tests/CONTRIBUTING.md), [`docs/developer/testing-strategy.md`](docs/developer/testing-strategy.md) |
| Change examples | [`examples/README.md`](examples/README.md); `test-examples-functional.yml` validates them |
| Understand how a scan flows | `argus/core/engine.py`, the architecture page built by `scripts/docsite/architecture.py`, or the `components` and `data_flow` keys of `.ai/architecture.yaml` |
| Learn why something is the way it is | `python -m scripts.ci.adr_records list`, then the ADR it points to |
| Diagnose a known error | Search `.ai/errors.yaml` and [`docs/troubleshooting/`](docs/troubleshooting/) |
| Use Argus rather than develop it | [`README.md`](README.md), [`QUICK-START.md`](QUICK-START.md), [`docs/scanners.md`](docs/scanners.md) |

## Invariants

- **Python and pytest only.** The SDK, every action script and every test are Python; no Bash or Node.js action logic. One test framework (pytest) and one coverage tool (pytest-cov).
- **Coverage stays at 80% or above.** `pytest.ini` enforces it (`--cov-fail-under=80`).
- **Some scanners stay composite-only.** If a tool's main signal comes from the GitHub API (it needs `GITHUB_TOKEN` and a `pull_request` context), or its licence stops off-platform users from running its CLI, it lives only under `.github/actions/scanner-<name>/` with no SDK port. `scanner-codeql` and `scanner-dependency-review` are the two cases. The full test is ADR-021 in `.ai/decisions.yaml`.
- **Never commit to `main`.** Work on an issue branch and open a draft PR (see [Issues, branches, and records](#issues-branches-and-records)).
- **No secrets in the repo.** Registry credentials and tokens go in GitHub Secrets, never in config files. In examples and docs, pin actions to a release tag, not a branch.

### Secret-leak audit

Do this for every new or changed scanner. If the tool's raw output can contain literals matched in source code (passwords, API keys, the `code` excerpt behind a finding), drop or redact those fields before building the `Finding`: `argus.core.redact.redact_secret(value)` for fields holding the raw value, `redact_secret_in_message(msg, value)` for descriptions that interpolate it. Add a test asserting the original literal never appears in `Finding.to_dict()` JSON. `Finding.__post_init__` runs a pattern-based second pass for known token prefixes (GitHub PATs, AWS keys, Slack tokens, JWTs, PEM keys), but that's a backstop: anything without a recognisable prefix relies on the first pass. Full checklist: [`docs/mcp.md`, "Secrets handling"](docs/mcp.md#secrets-handling).

## Develop and test

```bash
uv sync --locked --all-extras                  # package, every extra and the dev group (deps pinned in uv.lock)
uv sync --locked --all-extras --group hooks    # also pre-commit
uv lock                                        # after changing a dependency range in pyproject.toml

pytest                    # full run with coverage
pytest --no-cov -q        # fast
pre-commit run --all-files
```

CI also runs `python -m scripts.ci.check_version_refs`, `check_version_drift`, `check_cli_docs`, `check_architecture_sync` and `check_ai_index`. Run the relevant one if you touch versions, the CLI, the scanner, linter and reporter registries, or anything under `.ai/`.

Commits follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat(scanner-bandit): ...`, `fix: ...`, `docs: ...`). PRs use `.github/PULL_REQUEST_TEMPLATE.md`; keep its `Closes #<issue>` line at the top.

## Releases

Releases are cut by hand from the **Release** workflow (Actions → Release → Run workflow), so merging to `main` ships nothing on its own; a push to `main` only runs the dry-run preview. release-it bumps every version reference (`version.yaml`, `argus/__init__.py`, action tags in docs and examples), so never edit version numbers by hand.

There is no long-lived beta branch. To try a batch of merged changes before the final release, cut an `X.Y.Z-rc.N` prerelease (ADR-500); `:latest` doesn't move and pip skips it unless asked. Steps: [`docs/developer/release-management.md`, "Trying a big change before it ships"](docs/developer/release-management.md#trying-a-big-change-before-it-ships).

## Keeping `.ai/` in sync

`.ai/` holds structured context in the AICaC format. Update it in the same PR as the change:

| When you... | Update |
|---|---|
| Make a design decision | New `.ai/decisions/ADR-<issue>.yaml` (see [`docs/developer/adr-records.md`](docs/developer/adr-records.md)) |
| Add a scanner, linter, reporter or CLI subcommand | `.ai/architecture.yaml` or `.ai/context.yaml`; `check_architecture_sync` fails CI until you do |
| Add a component or change how components connect | `.ai/architecture.yaml` |
| Add a common task or command | `.ai/workflows.yaml` |
| Fix an error others will hit | `.ai/errors.yaml` |

Then run `python -m scripts.ci.check_ai_index --fix` to regenerate `.ai/index.yaml`; CI fails if it's stale.

## Why things are this way

| Decision | Reason |
|---|---|
| SDK as the primary interface | Works the same locally and in any CI |
| Composite actions, not reusable workflows | GHES doesn't support cross-repo `workflow_call` |
| SARIF output | GitHub Security tab integration; an industry standard |
| Python for everything | One language, one test framework, one coverage number |
| Tests next to the code they test | Each action and SDK module carries its own `tests/` |
| Issue-keyed branches and ADRs | Issue numbers are unique, so parallel PRs never pick the same ADR ID or touch the same lines (ADR-483) |
