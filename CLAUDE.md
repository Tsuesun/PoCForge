# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a CVE-to-PoC Generator that transforms GitHub Security Advisory fix commits into practical vulnerability demonstrations. The tool extracts fix commits from advisories and uses AI to generate Proof-of-Concept code, attack vectors, and test cases for security research and education.

## Important Guidelines

**NEVER add co-author attribution or "Generated with Claude Code" to commits or pull requests.** The user has explicitly requested not to include any attribution to Claude or AI assistance.

## Architecture

- **main.py**: Core application entry point with CVE discovery and PoC generation
- **cve_tracker/**: Modular package structure:
  - `poc_generator.py`: AI-powered PoC generation from fix commits
  - `github_search.py`: Advisory reference extraction and repository discovery
  - `claude_analysis.py`: AI analysis for commit screening and detailed analysis
  - `security_scoring.py`: Security relevance scoring algorithms
  - `package_mapping.py`: Package-to-repository mapping logic
- **Project uses uv** for dependency management instead of pip
- **Advisory-first approach** with AI fallback for maximum accuracy and efficiency

## Development Commands

### Running the Application
```bash
# Run the CVE-to-PoC generator (basic mode)
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