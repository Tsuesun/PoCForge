#!/bin/bash
# Setup git hooks for the project

echo "Setting up git hooks..."

# Create hooks directory if it doesn't exist
mkdir -p .git/hooks

# Copy pre-push hook
cp pre-push .git/hooks/pre-push

# Make it executable
chmod +x .git/hooks/pre-push

echo "✅ Pre-push hook installed!"
echo ""
echo "The hook will run:"
echo "  - ruff format --check (formatting)"
echo "  - ruff check (linting)" 
echo "  - mypy (type checking)"
echo ""
echo "To bypass the hook (not recommended): git push --no-verify"
