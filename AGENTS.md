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
2. **Name the branch after the issue.** Use `<prefix>/<issue>-<short-description>`, with the issue number right after the prefix: `feat/483-issue-keyed-records`. For a sub-issue, use the sub-issue's number, never the parent's or the epic's. A ruleset rejects pushes whose branch doesn't start with an allowed prefix. Pick the one that matches the change: `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `test`, `ci`, `build`, `revert` or `hotfix`. Coding agents use these too. The ruleset also lets `copilot/`, `claude/`, `dependabot/`, `renovate/` and `aicac/` through for tools that pick their own branch names, but when you choose the name, use a type prefix.
3. **Check nobody has it, then open a draft PR.** Look for an open PR linked to the issue and for a branch already named for it. If either exists, stop and ask on the issue before doing anything else.
   ```bash
   gh issue view <issue> --json closedByPullRequestsReferences --jq '.closedByPullRequestsReferences[].url'
   gh pr list --state open --search "<issue>"
   git ls-remote --heads origin "*/<issue>-*"
   ```
   If both come back empty, push your first commit and open a draft PR right away (`gh pr create --draft`), so everyone can see the issue is taken.
4. **Link the issue.** Put `Closes #<issue>` in the PR body when the PR finishes the issue, or `Refs #<issue>` when it's partial work. The PR template has the line.
5. **Record decisions under the issue number.** A new ADR is one file, `.ai/decisions/ADR-<issue>.yaml`. See [Adding an ADR](#adding-an-adr).

Nobody edits an ADR index by hand. `python -m scripts.ci.adr_records list` builds it at read time from both stores. The **ADR Records** workflow (`.github/workflows/adr-records.yml`) checks every PR and every push to `main`.

### Adding an ADR

```bash
python -m scripts.ci.adr_records new --title "Short decision title"   # issue number comes from the branch
```

That writes `.ai/decisions/ADR-<issue>.yaml`. Fill it in:

| Field | Required | Notes |
|-------|----------|-------|
| `id` | yes | `ADR-<issue>`, same as the file name |
| `title` | yes | |
| `date` | | `'YYYY-MM-DD'` |
| `status` | yes | `proposed`, `accepted`, `rejected`, `deprecated` or `superseded` |
| `context` | yes | The problem that made the decision necessary |
| `decision` | yes | What was decided |
| `rationale`, `alternatives_considered`, `consequences`, `implementation` | | Same shapes as in `.ai/decisions.yaml` |
| `affects_components` | | Component IDs from `.ai/architecture.yaml` |
| `supersedes` | | List of ADR IDs this one replaces |

Rules:

- **Never add entries to `.ai/decisions.yaml`.** It holds ADR-001 to ADR-044 and is closed to new ones. You can still edit an existing entry there (status, wording).
- **Never renumber an ADR.** Legacy IDs are zero-padded three digits (`ADR-007`). Issue-keyed IDs are the bare issue number (`ADR-483`), never padded and never below 100, so the two can't collide.
- **One ADR per PR**, keyed to that PR's issue. A PR with two decisions either records both in its one ADR or gets split into two issues.
- **Superseding a legacy ADR:** set the old entry's `status: superseded` and list it under `supersedes` in the new file. Don't put the new ID in the old entry's `superseded_by`; the AICaC validator only resolves IDs inside `.ai/decisions.yaml`.
- See every ADR: `python -m scripts.ci.adr_records list` (add `--format yaml` or `--format json` for machine-readable output).
- Check before you push: `python -m scripts.ci.adr_records check --branch "$(git branch --show-current)" --base origin/main`

### If the check fails

| Message | Fix |
|---------|-----|
| `this branch is for issue #N, so its ADR must be .ai/decisions/ADR-N.yaml` | `git mv` the file to `ADR-N.yaml` and set `id: ADR-N`. If the ADR really belongs to another issue, it goes in that issue's PR. |
| `a PR that adds an ADR needs a branch named <prefix>/<issue>-<description>` | The branch has no issue number. See [Moving to a branch with an issue number](#moving-to-a-branch-with-an-issue-number). |
| `ADR-0NN is a new entry, but this file is closed to new ADRs` | Move the entry out of `.ai/decisions.yaml` into `.ai/decisions/ADR-<issue>.yaml`. |
| `ADR number N is used more than once` or `duplicate key` | Two entries share an ID, usually from a merge. Keep the one already on `main` and key yours to your issue. |
| `ADR files are named ADR-<issue>.yaml` or `issue-keyed ADR numbers start at 100` | Rename the file: no zero padding, `.yaml` extension, your issue number. |
| `'<field>' is required`, `unknown component`, `unknown ADR` | Fix the field in the ADR file. |
| Warning: `branch '...' has no issue number` | Only a warning. Fine for Dependabot, Renovate and other automated PRs. For anything else, move to a branch with an issue number. |

Pull requests from forks run the same check with a read-only token and no secrets. The ruleset can't enforce branch names in a fork, so a fork branch without an issue number gets the warning, and only fails if it adds an ADR.

### Moving to a branch with an issue number

**Never rename a PR's head branch on GitHub.** Renaming the head branch closes the PR. Push a new, correctly named branch and open a new PR instead:

```bash
git switch -c feat/<issue>-<short-description>     # starts from your current branch, keeps its commits
# If the PR adds an ADR: git mv it to .ai/decisions/ADR-<issue>.yaml, set its id, commit
git push -u origin feat/<issue>-<short-description>
gh pr create --draft --body "Closes #<issue>. Replaces #<old-pr>."
gh pr close <old-pr> --comment "Moved to #<new-pr>."
```

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

CI also runs `python -m scripts.ci.check_version_refs`, `check_cli_docs` and `check_architecture_sync`. Run the relevant one if you touch versions, the CLI, or the scanner, linter and reporter registries.

Commits follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat(scanner-bandit): ...`, `fix: ...`, `docs: ...`). PRs use `.github/PULL_REQUEST_TEMPLATE.md`; keep its `Closes #<issue>` line at the top.

## Releases

Releases are cut by hand from the **Release** workflow (Actions → Release → Run workflow), so merging to `main` ships nothing on its own; a push to `main` only runs the dry-run preview. release-it bumps every version reference (`version.yaml`, `argus/__init__.py`, action tags in docs and examples), so never edit version numbers by hand.

### Trying a big change before it ships

There is no long-lived beta branch. Big batches of related PRs merge to `main` like any other PR, and a prerelease is how they get tried before the final release (ADR-500):

1. **One PR:** every same-repo PR that touches `argus/` or `pyproject.toml` publishes a `<version>.devN` build to TestPyPI.
2. **A batch:** once the batch is on `main`, run the Release workflow with `releaseType: prerelease` (or `minor` / `major`) and `preReleaseId: rc`. That cuts `X.Y.Z-rc.N`: the GitHub release is marked as a prerelease, the wheel goes to PyPI as `X.Y.ZrcN`, and the images get an `:X.Y.Z-rc.N` tag. `:latest` does not move.
3. **Try it:** `pip install --pre argus-security==X.Y.ZrcN`, or pull `ghcr.io/huntridge-labs/argus/<image>:X.Y.Z-rc.N`. pip and uv skip prereleases unless asked, so nobody gets one by accident.
4. **Ship it:** run the Release workflow again with the matching `releaseType` and no `preReleaseId` to cut `X.Y.Z`. That one moves `:latest`.

Prerelease tags are kept like any other version tag (the GHCR prune job only removes non-version tags), because the rc wheel on PyPI pins those image digests.

## Keeping `.ai/` in sync

`.ai/` holds structured context in the AICaC format. Update it in the same PR as the change:

| When you... | Update |
|---|---|
| Make a design decision | New `.ai/decisions/ADR-<issue>.yaml` (see [Adding an ADR](#adding-an-adr)) |
| Add a scanner, linter, reporter or CLI subcommand | `.ai/architecture.yaml` or `.ai/context.yaml`; `check_architecture_sync` fails CI until you do |
| Add a component or change how components connect | `.ai/architecture.yaml` |
| Add a common task or command | `.ai/workflows.yaml` |
| Fix an error others will hit | `.ai/errors.yaml` |

## Why things are this way

| Decision | Reason |
|---|---|
| SDK as the primary interface | Works the same locally and in any CI |
| Composite actions, not reusable workflows | GHES doesn't support cross-repo `workflow_call` |
| SARIF output | GitHub Security tab integration; an industry standard |
| Python for everything | One language, one test framework, one coverage number |
| Tests next to the code they test | Each action and SDK module carries its own `tests/` |
| Issue-keyed branches and ADRs | Issue numbers are unique, so parallel PRs never pick the same ADR ID or touch the same lines (ADR-483) |
