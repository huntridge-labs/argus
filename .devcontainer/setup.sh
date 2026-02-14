#!/bin/bash
set -e

echo "Setting up development environment..."

# Install Node dependencies
echo "Installing Node.js dependencies..."
npm ci

# Create Python virtual environment
echo "Setting up Python virtual environment..."
if [ -d ".dev.venv" ]; then
    echo "Python virtual environment already exists. Skipping creation."
else
    python3 -m venv .dev.venv
fi

# Activate Python virtual environment
source .dev.venv/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
pip install pre-commit

# Setup pre-commit hooks (using absolute path)
echo "Installing pre-commit hooks..."
git config --unset-all core.hooksPath || true
pre-commit install --install-hooks
pre-commit install --hook-type pre-push

echo "Development environment ready!"
echo ""
echo "Quick start:"
echo "  pytest                    # Run all tests"
echo "  pytest                    # Run tests with coverage"
echo "  pre-commit run --all-files # Run all hooks"
echo ""
echo "Note: Python venv (.dev.venv) is auto-activated in new terminals"
