# CVE to Fix Tracker

A tool that fetches recent CVEs (Common Vulnerabilities and Exposures) from GitHub's security advisory API and automatically correlates them with potential security fixes in the affected repositories.

## Features

- **CVE Discovery**: Fetches recent security advisories from GitHub's global advisory database
- **Repository Mapping**: Automatically maps vulnerable packages to their likely GitHub repositories
- **Fix Detection**: Searches for security-related pull requests and commits that address vulnerabilities
- **Smart Scoring**: Ranks potential fixes based on relevance using security keywords and patterns
- **Multi-Ecosystem Support**: Handles npm, PyPI, Maven, NuGet, and other package ecosystems
- **ReDoS Detection**: Specialized detection for Regular Expression Denial of Service vulnerabilities

## Requirements

- Python 3.8+
- [uv](https://github.com/astral-sh/uv) package manager
- GitHub Personal Access Token (optional, but recommended for higher rate limits)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Tsuesun/cvetofix.git
cd cvetofix
```

2. Install dependencies using uv:
```bash
uv sync
```

3. Set up your GitHub token (optional but recommended):
```bash
export GITHUB_TOKEN="your_github_token_here"
```

## Usage

### Basic Usage

Run the CVE tracker to find vulnerabilities from the last 24 hours:

```bash
uv run main.py
```

### With GitHub Token

For higher rate limits (5000 requests/hour vs 60):

```bash
GITHUB_TOKEN="your_token" uv run main.py
```

### Example Output

```
CVE: CVE-2025-53539
Summary: fastapi-guard is vulnerable to ReDoS through inefficient regex
Severity: MEDIUM
Published: 2025-07-07 23:36:39+00:00

Package: fastapi-guard (pip)
   Vulnerable: <= 3.0.0
   Patched: None
   Found 8 potential security fixes:
      fix: support IPv6 addresses in SecurityMiddleware using ip_address() (Score: 9)
         https://github.com/rennf93/fastapi-guard/commit/b5f0df8fbe8a1e134d64bd6ddb82a5063454b39d
         rennf93/fastapi-guard
         2025-06-19
      Fixed custom_response_modifier implementation (Score: 9)
         https://github.com/rennf93/fastapi-guard/pull/47
         rennf93/fastapi-guard
```

## How It Works

1. **CVE Fetching**: Queries GitHub's global security advisory API for recent vulnerabilities
2. **Package Mapping**: Maps vulnerable packages to potential repository names using ecosystem-specific patterns:
   - **npm**: Handles org/package patterns (`@org/package` → `org/package`)
   - **PyPI**: Converts between hyphens and underscores (`my-package` ↔ `my_package`)
   - **Maven/Gradle**: Extracts artifact names from group:artifact patterns
   - **NuGet**: Direct package name mapping
3. **Repository Discovery**: Searches GitHub for repositories matching package names, prioritizing by stars
4. **Fix Detection**: Searches recent PRs and commits for security-related content using:
   - **Security Keywords**: `security`, `vulnerability`, `CVE`, `fix`, `patch`, `exploit`, `XSS`, `CSRF`, `redos`, etc.
   - **Pattern Matching**: Identifies commits/PRs that start with "fix:", "security:", "patch:"
   - **CVE References**: Direct CVE ID mentions get highest priority scoring
5. **Relevance Scoring**: Ranks findings based on:
   - Direct CVE matches (10 points)
   - Security keywords (2 points each)
   - "fix" + security terms (3 points)
   - Title patterns (2 points)

## Development

### Code Quality

The project uses several tools to maintain code quality:

```bash
# Format code
uv run ruff format .

# Lint code
uv run ruff check .

# Type checking
uv run mypy .

# Run tests
uv run pytest

# Run all checks
uv run ruff format . && uv run ruff check . && uv run mypy . && uv run pytest
```

### Git Hooks

Install pre-push hooks to ensure code quality:

```bash
./setup-hooks.sh
```

This will automatically run formatting, linting, and type checking before each push.

### Testing

The project includes comprehensive tests covering all major functions:

```bash
# Run all tests
uv run pytest

# Run tests with verbose output
uv run pytest -v

# Run specific test file
uv run pytest tests/test_main.py

# Run specific test
uv run pytest tests/test_main.py::TestGetPotentialRepos::test_npm_package_without_org
```

**Test Coverage:**
- **Package-to-Repository Mapping**: Tests for all supported ecosystems (npm, PyPI, Maven, NuGet)
- **Security Scoring**: Tests for PR and commit relevance scoring algorithms
- **Repository Discovery**: Tests for GitHub API repository search functionality
- **Search Functions**: Tests for PR and commit search with mocked GitHub API
- **Integration**: End-to-end tests ensuring security keywords detect real vulnerabilities

### Project Structure

```
cvetofix/
├── main.py              # Main application entry point
├── cve_tracker/         # Core package modules
│   ├── __init__.py      # Package initialization and exports
│   ├── package_mapping.py    # Package-to-repository mapping logic
│   ├── security_scoring.py   # Security relevance scoring algorithms
│   └── github_search.py      # GitHub API search and discovery
├── tests/               # Test suite
│   ├── __init__.py      # Test package initialization
│   └── test_main.py     # Comprehensive tests for all functions
├── CLAUDE.md            # Development guidance for Claude Code
├── README.md            # This file
├── pyproject.toml       # Project configuration and dependencies
├── uv.lock              # Lock file for reproducible builds
├── setup-hooks.sh       # Git hooks installation script
└── pre-push             # Pre-push hook for code quality
```

## Key Modules

### **main.py**
- `fetch_recent_cves()`: Main function that orchestrates CVE discovery and analysis

### **cve_tracker.package_mapping**
- `get_potential_repos()`: Maps package names to likely repository names based on ecosystem

### **cve_tracker.security_scoring**
- `calculate_security_relevance_score()`: Scores PRs for security relevance
- `calculate_commit_security_relevance_score()`: Scores commits for security relevance
- `SECURITY_KEYWORDS`: Centralized list of security-related terms

### **cve_tracker.github_search**
- `find_repository()`: Discovers repositories using multiple search strategies
- `search_security_prs()`: Finds security-related pull requests in repositories
- `search_security_commits()`: Finds direct security fix commits (catches hotfixes)
- `search_prs_in_repo()`: Searches PRs within a specific repository
- `search_commits_in_repo()`: Searches commits within a specific repository

## Configuration

### Environment Variables

- `GITHUB_TOKEN`: Personal access token for higher rate limits (recommended)

### Rate Limits

- **Without token**: 60 requests per hour
- **With token**: 5000 requests per hour

### Search Limits

To balance API usage with coverage:
- **PRs**: Last 10 pull requests per repository
- **Commits**: Last 50 commits per repository
- **Results**: Top 5 PRs and top 3 commits per CVE

## Troubleshooting

### Rate Limit Issues

If you hit rate limits:
1. Set a `GITHUB_TOKEN` environment variable
2. Reduce the number of CVEs processed (modify the limit in `main.py`)
3. Wait for the rate limit to reset (shown in error messages)

### Repository Not Found

Some packages may not have discoverable repositories:
- Package names don't match repository names
- Repositories are private or archived
- Package ecosystems use different naming conventions

### No Security Fixes Found

This can happen when:
- Fixes haven't been implemented yet
- Fixes are in private repositories
- Security patches are applied without clear commit messages
- The vulnerability is in a dependency, not the main package

## Future Improvements

- **Date-range filtering**: Search commits around CVE publication dates
- **Dependency scanning**: Check if fixes exist in dependency repositories
- **Machine learning**: Improve fix detection with ML-based scoring
- **Database storage**: Cache results to avoid re-searching
- **Web interface**: Browser-based dashboard for results
- **Notifications**: Alert system for new CVEs with fixes

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run the quality checks (`uv run ruff format . && uv run ruff check . && uv run mypy .`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is open source. See the repository for license details.

## Acknowledgments

- [PyGithub](https://github.com/PyGithub/PyGithub) for GitHub API integration
- [GitHub Security Advisory API](https://docs.github.com/en/rest/security-advisories) for CVE data
- [uv](https://github.com/astral-sh/uv) for fast Python package management