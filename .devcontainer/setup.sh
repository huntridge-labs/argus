#!/bin/bash
set -e

echo "Setting up development environment..."

# Install Node dependencies (pnpm-lock.yaml; the version comes from
# package.json's packageManager field via corepack)
echo "Installing Node.js dependencies..."
corepack enable
pnpm install --frozen-lockfile

# Create Python virtual environment
echo "Setting up Python virtual environment..."
if [ -d ".dev.venv" ]; then
    echo "Python virtual environment already exists. Skipping creation."
else
    python3 -m venv .dev.venv
fi

# Activate Python virtual environment
source .dev.venv/bin/activate

# Install Python dependencies from uv.lock (ADR-043): the package itself
# (editable), every optional extra, the dev group (tests) and the hooks group
# (pre-commit). uv is bootstrapped into the venv; --active syncs into this
# venv instead of .venv, and --inexact keeps uv itself installed.
echo "Installing Python dependencies..."
pip install "uv==0.13.1"
uv sync --locked --all-extras --group hooks --active --inexact

# Setup pre-commit hooks (using absolute path)
echo "Installing pre-commit hooks..."
git config --unset-all core.hooksPath || true
pre-commit install --install-hooks
pre-commit install --hook-type pre-push

echo "Development environment ready!"
echo ""
echo "Quick start:"
echo "  argus --version           # Verify CLI entrypoint"
echo "  pytest                    # Run all tests"
echo "  pytest --cov              # Run tests with coverage"
echo "  pre-commit run --all-files # Run all hooks"
echo ""
echo "Note: Python venv (.dev.venv) is auto-activated in new terminals"
