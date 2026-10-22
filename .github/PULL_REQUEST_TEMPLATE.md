Closes #
<!-- Every PR starts from an issue. Use "Refs #N" instead if this PR is only part of the work. -->

## Description
Briefly describe the changes in this pull request.

## Changes Made
- [ ] Added new scanner/workflow
- [ ] Modified existing scanner/workflow
- [ ] Updated documentation
- [ ] Fixed bug
- [ ] Other (please specify)

### Details
Provide more details about the changes, including:
- Which workflows/scanners are affected?
- What new features or fixes are included?
- Any breaking changes?

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed
- [ ] Tested with different scanner combinations

### Test Results
Paste any relevant test output or describe testing performed.

## Security Considerations
- [ ] No security impact
- [ ] Security enhancement
- [ ] Potential security implications (explain below)

### Security Details
If applicable, describe any security-related changes, new vulnerabilities addressed, or potential risks.

## AI Context Updates (.ai/)
If this PR changes project structure, commands, or behavior, update the relevant `.ai/` files:

- [ ] `.ai/architecture.yaml` updated (if components/structure changed)
- [ ] `.ai/workflows.yaml` updated (if commands/tasks changed)
- [ ] New ADR added as `.ai/decisions/ADR-<issue>.yaml` (if design decision made; never append to `.ai/decisions.yaml`)
- [ ] `.ai/errors.yaml` updated (if common error addressed)
- [ ] N/A - No .ai/ updates needed

See the `.ai/` maintenance table in `AGENTS.md` for guidance.

## Checklist
- [ ] Branch is named `<prefix>/<issue>-<description>` with this PR's issue number (see `AGENTS.md`, "Issues, branches, and records")
- [ ] Code follows project style guidelines
- [ ] Documentation updated (if applicable)
- [ ] Changelog updated (if applicable)
- [ ] All tests pass
- [ ] Reviewed by at least one maintainer
- [ ] **Reviewed CONTRIBUTING.md guidelines**

### For New Scanners/Actions (if applicable)
- [ ] Composite action created (`.github/actions/scanner-*`)
- [ ] Parser and summary scripts included
- [ ] Unit tests added (`.github/actions/*/tests/`)
- [ ] Action documented (README.md in action directory)
- [ ] Added to actions catalog (`.github/actions/README.md`)
- [ ] Examples updated
- [ ] No breaking changes to existing scanners

## Related Issues
Other related issues or PRs (the issue this PR closes goes on the first line).

## Screenshots/Logs (if applicable)
Add any relevant screenshots, logs, or other evidence of the changes.
