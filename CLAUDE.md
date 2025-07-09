# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PoCForge is a CVE-to-PoC Generator that transforms GitHub Security Advisory fix commits into practical vulnerability demonstrations. The tool extracts fix commits from advisories and uses AI to generate Proof-of-Concept code, attack vectors, and test cases for security research and education.

## Important Guidelines

**NEVER add co-author attribution or "Generated with Claude Code" to commits or pull requests.** The user has explicitly requested not to include any attribution to Claude or AI assistance.

**Avoid marketing language in PRs and commits.** Use straightforward, technical descriptions. Avoid words like "powerful", "amazing", "revolutionary", etc. The code should speak for itself.

## Architecture

- **main.py**: Core application entry point with CVE discovery and PoC generation
- **cve_tracker/**: Modular package structure:
  - `poc_generator.py`: AI-powered PoC generation from fix commits using Claude API
  - `github_search.py`: Advisory reference extraction (commit URLs from security advisories)
  - `config.py`: Configuration management for API keys (GitHub token, Anthropic API key)
- **Project uses uv** for dependency management instead of pip
- **Advisory-first approach**: 95%+ of GitHub Security Advisories contain direct fix commit references
- **Simplified architecture**: Removed complex AI analysis and repository discovery logic

## Development Commands

### Running the Application
```bash
# Run PoCForge (basic mode)
uv run main.py

# Run with GitHub token for higher rate limits
GITHUB_TOKEN=your_token uv run main.py

# Run with full PoC generation capabilities (requires Claude API)
GITHUB_TOKEN=your_token ANTHROPIC_API_KEY=your_claude_key uv run main.py
```

### Code Quality Tools
```bash
# Format code
uv run ruff format .

# Check formatting
uv run ruff format --check .

# Run linting
uv run ruff check .

# Fix auto-fixable lint issues
uv run ruff check --fix .

# Run type checking
uv run mypy .
```

### Testing and Coverage
```bash
# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=. --cov=cve_tracker

# Generate coverage report
uv run coverage report

# Generate HTML coverage report
uv run coverage html

# Run coverage and generate both terminal and HTML reports
uv run pytest --cov=. --cov=cve_tracker --cov-report=term-missing --cov-report=html

# View coverage percentage only
uv run coverage report --show-missing
```

#### Coverage Integration
- **CI**: GitHub Actions automatically runs coverage on all PRs and pushes
- **Reports**: HTML coverage reports generated in `htmlcov/` directory
- **Current Coverage**: 48.05% baseline with detailed missing line reports

### Git Hooks
- Pre-push hook automatically runs ruff format --check, ruff check, and mypy
- Install hooks: `./setup-hooks.sh`
- Bypass hook (not recommended): `git push --no-verify`

### Git Workflow
```bash
# Squash commits on feature branches
git rebase -i HEAD~n  # where n is number of commits to squash

# Rebase feature branch onto master before merging
git checkout feature-branch
git rebase master

# Alternative: fetch and rebase in one command
git pull --rebase origin master
```

**Preferred workflow:**
1. Create feature branch from master
2. Make commits during development
3. Before creating PR: squash commits into logical units
4. Rebase onto latest master to avoid merge commits
5. Create PR with clean commit history

## Configuration

The application uses a config.json file for API keys:
```json
{
  "github_token": "your_github_token",
  "anthropic_api_key": "your_anthropic_api_key"
}
```

Environment variables override config file values:
- `GITHUB_TOKEN`: GitHub personal access token
- `ANTHROPIC_API_KEY`: Anthropic Claude API key

## Key Dependencies

- **PyGithub**: GitHub API client for fetching security advisories
- **ruff**: Code formatting and linting
- **mypy**: Type checking