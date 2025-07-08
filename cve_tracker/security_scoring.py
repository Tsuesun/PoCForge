"""
Security relevance scoring functionality.

Provides scoring algorithms to rank PRs and commits based on their security relevance.
"""

from typing import Any, List, Optional

from github.PullRequest import PullRequest

# Security-related keywords used for scoring
SECURITY_KEYWORDS = [
    "security",
    "vulnerability",
    "CVE",
    "fix",
    "patch",
    "exploit",
    "XSS",
    "SQL injection",
    "CSRF",
    "authentication",
    "authorization",
    "sanitize",
    "validate",
    "escape",
    "buffer overflow",
    "DoS",
    "redos",
    "privilege escalation",
    "code injection",
    "path traversal",
    "regex",
]


def calculate_security_relevance_score(
    pr: PullRequest, security_keywords: List[str], cve_id: Optional[str]
) -> int:
    """
    Calculate a relevance score for a PR based on security indicators.

    Args:
        pr: Pull request to evaluate
        security_keywords: List of security-related keywords
        cve_id: CVE ID to search for

    Returns:
        Relevance score (higher = more relevant)
    """
    score = 0

    # Text to search (title + body)
    search_text = (pr.title + " " + (pr.body or "")).lower()

    # High-value matches
    if cve_id and cve_id.lower() in search_text:
        score += 10  # Direct CVE match

    # Security keyword matches
    for keyword in security_keywords:
        if keyword.lower() in search_text:
            score += 2

    # Additional indicators
    if "fix" in search_text and any(
        word in search_text for word in ["security", "vulnerability", "CVE"]
    ):
        score += 3  # "fix" + security terms

    if pr.title.lower().startswith(("fix", "security", "patch")):
        score += 2  # Title starts with fix/security/patch

    return score


def calculate_commit_security_relevance_score(
    commit: Any, security_keywords: List[str], cve_id: Optional[str]
) -> int:
    """
    Calculate a relevance score for a commit based on security indicators.

    Args:
        commit: Commit to evaluate
        security_keywords: List of security-related keywords
        cve_id: CVE ID to search for

    Returns:
        Relevance score (higher = more relevant)
    """
    score = 0

    # Text to search (commit message)
    search_text = commit.commit.message.lower()

    # High-value matches
    if cve_id and cve_id.lower() in search_text:
        score += 10  # Direct CVE match

    # Security keyword matches
    for keyword in security_keywords:
        if keyword.lower() in search_text:
            score += 2

    # Additional indicators
    if "fix" in search_text and any(
        word in search_text for word in ["security", "vulnerability", "CVE", "redos"]
    ):
        score += 3  # "fix" + security terms

    if search_text.startswith(("fix", "security", "patch")):
        score += 2  # Message starts with fix/security/patch

    return score
