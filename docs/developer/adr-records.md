# ADR records

How to add an architecture decision record (ADR), what the **ADR Records** check enforces, and how to fix it when it fails. The short rules (issue first, branch naming, draft PR, ADR file naming) are in [`AGENTS.md`, "Issues, branches, and records"](../../AGENTS.md#issues-branches-and-records). The reasoning is in [ADR-483](../../.ai/decisions/ADR-483.yaml).

There are two stores:

- `.ai/decisions.yaml` holds the legacy ADRs, ADR-001 to ADR-044. It is closed to new entries.
- `.ai/decisions/ADR-<issue>.yaml` holds one file per new ADR, keyed to its GitHub issue.

Nobody edits an ADR index by hand. `python -m scripts.ci.adr_records list` builds it at read time from both stores. The **ADR Records** workflow (`.github/workflows/adr-records.yml`) checks every PR and every push to `main`.

## Adding an ADR

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

- **Never add entries to `.ai/decisions.yaml`.** You can still edit an existing entry there (status, wording).
- **Never renumber an ADR.** Legacy IDs are zero-padded three digits (`ADR-007`). Issue-keyed IDs are the bare issue number (`ADR-483`), never padded and never below 100, so the two can't collide.
- **One ADR per PR**, keyed to that PR's issue. A PR with two decisions either records both in its one ADR or gets split into two issues.
- **Superseding a legacy ADR:** set the old entry's `status: superseded` and list it under `supersedes` in the new file. Don't put the new ID in the old entry's `superseded_by`; the AICaC validator only resolves IDs inside `.ai/decisions.yaml`.
- See every ADR: `python -m scripts.ci.adr_records list` (add `--format yaml` or `--format json` for machine-readable output).
- Check before you push: `python -m scripts.ci.adr_records check --branch "$(git branch --show-current)" --base origin/main`

## If the check fails

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

## Moving to a branch with an issue number

**Never rename a PR's head branch on GitHub.** Renaming the head branch closes the PR. Push a new, correctly named branch and open a new PR instead:

```bash
git switch -c feat/<issue>-<short-description>     # starts from your current branch, keeps its commits
# If the PR adds an ADR: git mv it to .ai/decisions/ADR-<issue>.yaml, set its id, commit
git push -u origin feat/<issue>-<short-description>
gh pr create --draft --body "Closes #<issue>. Replaces #<old-pr>."
gh pr close <old-pr> --comment "Moved to #<new-pr>."
```
