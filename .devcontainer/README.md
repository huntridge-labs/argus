# Development Container

This project includes a dev container configuration for consistent development environments.

## What's Included

- **Node.js** (Latest LTS) - For JavaScript tests and tooling
- **Python** (Latest) - For Python tests and pre-commit hooks
- **Ruby** (Latest) - For bashcov (bash coverage)
- **GitHub CLI** - For working with PRs and issues
- **VS Code Extensions** - Python, ESLint, ShellCheck, YAML, etc.

## Getting Started

### Option 1: VS Code (Recommended)

1. Install [VS Code](https://code.visualstudio.com/) and the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
2. Open this repository in VS Code
3. Click "Reopen in Container" when prompted (or run command: `Dev Containers: Reopen in Container`)
4. Wait for the container to build (~2-3 minutes first time)
5. All dependencies are ready! Run `npm test`

### Option 2: GitHub Codespaces

1. Click "Code" → "Codespaces" → "Create codespace on [branch]"
2. Wait for setup to complete
3. Start coding in the browser!

### Option 3: Local Setup (Traditional)

If you prefer not to use containers, install manually:

```bash
# Install dependencies
brew install node python ruby rbenv

# Install packages
npm ci
pip install pytest pytest-cov pyyaml pre-commit
gem install bashcov simplecov-cobertura

# Setup pre-commit
pre-commit install
```

## Benefits

✅ **Zero config** - Everything pre-installed and configured
✅ **Consistent** - Same environment for all contributors
✅ **Isolated** - Doesn't affect your local machine
✅ **Fast** - Cached builds, quick startup
✅ **Cloud ready** - Works with GitHub Codespaces

## Running Tests

```bash
# All tests
npm test

# With coverage
npm run test:coverage
npm run test:coverage:js
npm run test:coverage:python
npm run test:coverage:bash

# Pre-commit hooks
pre-commit run --all-files
```

## Troubleshooting

**Container won't start?**
- Ensure Docker is running
- Try: Dev Containers: Rebuild Container

**Dependencies missing?**
- Run: `.devcontainer/setup.sh`

**Need different versions?**
- Edit `.devcontainer/devcontainer.json` features
