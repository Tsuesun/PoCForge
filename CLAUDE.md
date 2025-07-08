# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a CVE (Common Vulnerabilities and Exposures) tracking tool that fetches recent security advisories from GitHub and correlates them with potentially affected packages. The tool uses PyGithub to access GitHub's security advisory API and identifies packages that may need security fixes.

## Architecture

- **main.py**: Core application with two main functions:
  - `fetch_recent_cves()`: Fetches GitHub security advisories from the last N hours
  - `get_potential_repos()`: Maps package names to potential repository search terms based on ecosystem patterns
- **Project uses uv** for dependency management instead of pip
- **Single-file architecture** with focused functionality for CVE correlation

## Development Commands

### Running the Application
```bash
# Run the CVE fetcher
uv run main.py

# Run with higher rate limits (requires GITHUB_TOKEN env var)
GITHUB_TOKEN=your_token uv run main.py
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

### Git Hooks
- Pre-push hook automatically runs ruff format --check, ruff check, and mypy
- Install hooks: `./setup-hooks.sh`
- Bypass hook (not recommended): `git push --no-verify`

## Package Ecosystem Mapping

The `get_potential_repos()` function handles different package ecosystems:
- **npm**: Handles org/package patterns and direct package names
- **pypi**: Converts between hyphens and underscores in package names
- **maven/gradle**: Extracts artifact names from group:artifact patterns
- **nuget**: Direct package name mapping

## Key Dependencies

- **PyGithub**: GitHub API client for fetching security advisories
- **ruff**: Code formatting and linting
- **mypy**: Type checking