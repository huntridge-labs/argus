<div align=center>

# Release Management with release-it

This project uses [release-it](https://github.com/release-it/release-it) for automated releases with conventional changelog generation.

</div>

## Overview

The release system automatically:
- Analyzes commits using conventional commit format
- Determines the next semantic version
- Generates a changelog
- Creates Git tags
- Publishes GitHub releases
- Updates version references in documentation
- Runs security checks

## Configuration

### Prerequisites
- **Node.js 22+** (required for release-it v19 and latest tooling)
- **npm 10.8+**
- **Release Bot Token** (required for automated releases)

### Release Bot Token Setup

Due to GitHub security restrictions, the automated release process requires a Personal Access Token (PAT) with workflow permissions to update workflow files during releases.

#### Creating the Token

1. **Create a fine-grained Personal Access Token:**
   - Go to: https://github.com/settings/tokens?type=beta
   - Click "Generate new token" (fine-grained)
   - Name it: `release-bot` or `workflow-updater`
   - Set expiration as appropriate for your security policy

2. **Configure token permissions:**
   - **Repository access**: Select "Only select repositories" → `huntridge-labs/argus`
   - **Repository permissions**:
     - `Contents`: **Read and write** (to push commits and tags)
     - `Workflows`: **Read and write** (to modify workflow files)
     - `Metadata`: **Read** (automatically included)

3. **Add token to repository:**
   - Go to repository: Settings → Environments → `prod`
   - Under "Environment secrets", click "Add secret"
   - Name: `RELEASE_BOT_TOKEN`
   - Value: Paste your token
   - Click "Add secret"

#### Why This Token Is Required

The release process automatically updates version references in workflow files (`.github/workflows/reusable-security-hardening.yml`) to keep them in sync with the released version. GitHub's default `GITHUB_TOKEN` cannot modify workflow files for security reasons, so a dedicated token with workflow permissions is required.

**Without this token:**
- ❌ Release will fail with permission error
- ❌ Workflow file versions will not be updated

**With this token:**
- ✅ Automated releases work seamlessly
- ✅ All version references stay synchronized
- ✅ Workflow files are automatically updated

### Main Configuration
The release configuration is stored in `.release-it.json`:
- Conventional changelog generation
- Semantic versioning
- Git tagging and GitHub releases
- Custom hooks for build processes

### Scripts Available
- `npm run release` - Interactive release (local development)
- `npm run release:dry` - Dry run to preview changes
- `npm run release:ci` - Non-interactive release (CI/CD)
- `npm run release:preview` - Preview with detailed changelog
- `npm run release:changelog` - Generate changelog preview only

## Release Preview Options

### 1. **Automatic PR Comments** ⭐ (Recommended)
When you open a pull request, GitHub Actions automatically comments with:
- **Impact assessment**: What type of version bump this PR will cause
- **PR-specific changes**: Only commits from this PR that affect releases
- **Quick summary**: Features, fixes, and breaking changes in this PR only
- **All PR commits**: For reference (not the entire project history)

### 2. **Local Preview**
Run preview commands locally on your feature branch:

```bash
# Basic dry run - shows FULL release since last tag
npm run release:dry

# Detailed preview with complete changelog - shows EVERYTHING
npm run release:preview

# Changelog only - shows ALL changes since last release
npm run release:changelog
```

**Note**: Local commands show the complete release that would happen, including all changes since the last release, not just your current changes.

### 3. **Manual GitHub Actions**
Trigger a release preview from GitHub Actions:
1. Go to Actions → Release workflow
2. Click "Run workflow"
3. Check "Dry run" option
4. Click "Run workflow"

This runs the full release process without making any changes and shows the **complete** changelog since the last release.

## Preview Scope Comparison

| Method | Scope | Best For |
|--------|-------|----------|
| **PR Comments** | 🎯 This PR only | Quick impact assessment |
| **Local Commands** | 📚 Full release | Complete release planning |
| **GitHub Actions Dry Run** | 📚 Full release | CI environment testing |

### When to Use Each

**Use PR Comments when:**
- You want to know what impact your specific changes will have
- You're reviewing someone else's PR
- You want a quick summary without overwhelming details

**Use Local Commands when:**
- You're preparing for a release
- You want to see the complete changelog
- You need to plan release communications

**Use GitHub Actions Dry Run when:**
- You want to test the full release pipeline
- You need to verify the release will work in CI
- You're troubleshooting release issues

## Understanding Release Previews

### Version Bump Indicators
- `0.1.0...0.2.0` - Minor version bump (new features)
- `0.1.0...0.1.1` - Patch version bump (bug fixes)
- `0.1.0...1.0.0` - Major version bump (breaking changes)
- `No release needed` - No conventional commits found

### Changelog Sections
- **Features** - `feat:` commits
- **Bug Fixes** - `fix:` commits
- **Performance Improvements** - `perf:` commits
- **Code Refactoring** - `refactor:` commits
- **Documentation** - `docs:` commits
- **Tests** - `test:` commits
- **Build System** - `build:` commits
- **Chores** - `chore:` commits

### What Triggers Releases
| Commit Type | Version Bump | Example |
|-------------|--------------|---------|
| `feat:` | minor (0.1.0 → 0.2.0) | `feat: add new API endpoint` |
| `fix:` | patch (0.1.0 → 0.1.1) | `fix: resolve memory leak` |
| `perf:` | patch (0.1.0 → 0.1.1) | `perf: optimize database queries` |
| `BREAKING CHANGE:` | major (0.1.0 → 1.0.0) | Any commit with breaking change footer |
| `docs:`, `chore:`, etc. | none | Documentation and maintenance |

## Usage

### Automated Releases (Recommended)
Releases are automatically triggered when code is pushed to the `main` branch:

1. Ensure your commits follow [conventional commit format](https://www.conventionalcommits.org/):
   ```
   feat: add new security scanning feature
   fix: resolve vulnerability in dependency parsing
   docs: update installation instructions
   chore: update dependencies
   ```

2. Push to main branch:
   ```bash
   git push origin main
   ```

3. The GitHub Actions workflow will:
   - Run tests
   - Determine version bump based on commits
   - Generate changelog
   - Create release

### Manual Releases
You can also trigger releases manually:

#### From GitHub UI
1. Go to Actions → Release workflow
2. Click "Run workflow"
3. Select release type: auto, patch, minor, major, or prerelease

#### From Command Line
```bash
# Interactive release (will prompt for version)
npm run release

# Dry run to see what would happen
npm run release:dry

# Specific version bumps
npm run release -- patch
npm run release -- minor
npm run release -- major
npm run release -- prerelease
```

## Commit Message Format

This project uses [Angular commit message conventions](https://github.com/angular/angular/blob/master/CONTRIBUTING.md#-commit-message-format):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types
- **feat**: A new feature (minor version bump)
- **fix**: A bug fix (patch version bump)
- **docs**: Documentation only changes
- **style**: Changes that do not affect the meaning of the code
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **perf**: A code change that improves performance
- **test**: Adding missing tests or correcting existing tests
- **build**: Changes that affect the build system or external dependencies
- **ci**: Changes to CI configuration files and scripts
- **chore**: Other changes that don't modify src or test files
- **revert**: Reverts a previous commit

### Breaking Changes
For breaking changes (major version bump), include `BREAKING CHANGE:` in the commit footer:

```
feat: change API response format

BREAKING CHANGE: The API now returns data in a different structure.
Users need to update their integration code.
```

## Version Bumping Rules

| Commit Type | Version Bump |
|-------------|--------------|
| `feat` | minor |
| `fix` | patch |
| `perf` | patch |
| `revert` | patch |
| Breaking Change | major |
| Others | no release |

## Security Integration

The release workflow includes security checks:
- NPM audit for high-severity vulnerabilities
- Dependency vulnerability scanning
- Build verification

## Troubleshooting

### Release Failed with Workflow Permission Error
**Error**: `refusing to allow a GitHub App to create or update workflow without 'workflows' permission`

**Solution**: Ensure the `RELEASE_BOT_TOKEN` is properly configured in the `prod` environment secrets. See [Release Bot Token Setup](#release-bot-token-setup) above.

### Release Failed
1. Check the GitHub Actions logs
2. Ensure all tests pass
3. Verify commit message format
4. Check for merge conflicts
5. Verify `RELEASE_BOT_TOKEN` is set in the `prod` environment

### Version Not Bumped
- Ensure commits follow conventional format
- Check if commit types warrant a release
- Verify the branch is `main` or `master`

### Manual Release Recovery
If automated release fails, you can manually create a release:

```bash
# Check current version
npm run release:dry

# Create release manually
npm run release -- --ci
```

## Migration from semantic-release

This project was migrated from semantic-release to release-it. Key differences:
- More interactive and user-friendly CLI
- Better plugin ecosystem
- Simpler configuration
- Enhanced GitHub integration
- More flexible hooks system

## Configuration Files

- `.release-it.json` - Main release configuration
- `package.json` - Dependencies and scripts
- `.github/workflows/release.yml` - CI/CD automation
- `CHANGELOG.md` - Generated release notes