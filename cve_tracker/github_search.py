"""
GitHub advisory reference extraction functionality.

Extracts fix commit URLs directly from GitHub Security Advisory references.
"""

import logging
import re
from typing import Any, Dict, List

from .constants import GITHUB_COMMIT_SCORE, GITHUB_COMMIT_SHA_LENGTH


def extract_commits_from_advisory_references(
    references: List[str],
) -> List[Dict[str, Any]]:
    """
    Extract commit URLs from advisory references.

    Args:
        references: List of reference URLs from the advisory

    Returns:
        List of commit info dictionaries with high confidence scores
    """
    commits = []
    commit_pattern = rf"https://github\.com/([^/]+/[^/]+)/commit/([a-f0-9]{{{GITHUB_COMMIT_SHA_LENGTH}}})"

    for ref in references:
        match = re.match(commit_pattern, ref)
        if match:
            repo_name = match.group(1)
            commit_sha = match.group(2)
            commits.append(
                {
                    "message": "Fix commit referenced in security advisory",
                    "url": ref,
                    "score": GITHUB_COMMIT_SCORE,  # Very high confidence - directly from advisory
                    "repo": repo_name,
                    "sha": commit_sha,
                    "date": "Referenced in advisory",
                    "source": "advisory_reference",
                }
            )
            logging.info(f"Found advisory-referenced commit: {commit_sha[:8]} in {repo_name}")

    return commits
