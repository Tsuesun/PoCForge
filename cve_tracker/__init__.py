"""
CVE Tracker - A tool for correlating CVEs with security fixes in repositories.
"""

from .claude_analysis import analyze_commit_with_claude
from .github_search import (
    find_repository,
    search_commits_in_repo,
    search_prs_in_repo,
    search_security_commits,
    search_security_prs,
)
from .package_mapping import get_potential_repos
from .security_scoring import (
    calculate_commit_security_relevance_score,
    calculate_security_relevance_score,
)

__all__ = [
    "get_potential_repos",
    "calculate_security_relevance_score",
    "calculate_commit_security_relevance_score",
    "find_repository",
    "search_security_prs",
    "search_security_commits",
    "search_prs_in_repo",
    "search_commits_in_repo",
    "analyze_commit_with_claude",
]
