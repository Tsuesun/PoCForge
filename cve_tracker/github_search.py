"""
GitHub repository search and discovery functionality.

Handles finding repositories and searching for security-related PRs and commits.
"""

import logging
from typing import Any, Dict, List, Optional

from github import Github
from github.Repository import Repository

from .security_scoring import (
    SECURITY_KEYWORDS,
    calculate_commit_security_relevance_score,
    calculate_security_relevance_score,
)


def find_repository(github_client: Github, repo_name: str) -> Optional[Repository]:
    """
    Find a repository by name, trying different search strategies.

    Args:
        github_client: GitHub API client
        repo_name: Repository name or search term

    Returns:
        Repository object if found, None otherwise
    """
    try:
        # Try direct repo access first (if it looks like owner/repo)
        if "/" in repo_name:
            return github_client.get_repo(repo_name)

        # Search for repositories
        repos = github_client.search_repositories(
            query=f"{repo_name} in:name", sort="stars", order="desc"
        )

        # Return the first (most starred) matching repository
        for repo in repos:
            if repo.name.lower() == repo_name.lower():
                return repo

        # If no exact match, return the first result
        if repos.totalCount > 0:
            return repos[0]  # type: ignore

    except Exception:
        pass

    return None


def search_security_prs(
    github_client: Github,
    repo_names: List[str],
    cve_id: Optional[str],
    package_name: str,
) -> List[Dict[str, Any]]:
    """
    Search for PRs that look like security fixes in the given repositories.

    Args:
        github_client: GitHub API client
        repo_names: List of repository names/search terms
        cve_id: CVE ID to search for (if available)
        package_name: Name of the affected package

    Returns:
        List of PR information dictionaries with title, url, and relevance score
    """
    security_prs = []

    for repo_name in repo_names:
        try:
            logging.info(f"Looking for repository: {repo_name}")
            # Try to find the repository
            repo = find_repository(github_client, repo_name)
            if not repo:
                logging.warning(f"Repository not found: {repo_name}")
                continue

            logging.info(f"Searching PRs in {repo.full_name}")

            # Search for PRs with security-related content
            prs = search_prs_in_repo(repo, SECURITY_KEYWORDS, cve_id)
            security_prs.extend(prs)
            logging.info(f"Found {len(prs)} relevant PRs in {repo.full_name}")

        except Exception as e:
            logging.error(f"Error searching {repo_name}: {e}")
            print(f"       ⚠️  Error searching {repo_name}: {e}")
            continue

    # Sort by relevance score (highest first)
    security_prs.sort(key=lambda x: x["score"], reverse=True)

    return security_prs[:5]  # Return top 5 most relevant PRs


def search_prs_in_repo(
    repo: Repository, security_keywords: List[str], cve_id: Optional[str]
) -> List[Dict[str, Any]]:
    """
    Search for security-related PRs in a specific repository.

    Args:
        repo: Repository to search
        security_keywords: List of security-related keywords
        cve_id: CVE ID to search for

    Returns:
        List of PR information dictionaries
    """
    prs = []

    try:
        logging.info(f"Getting recent PRs from {repo.full_name}")
        # Get recent PRs (last 10 to avoid rate limits)
        recent_prs = repo.get_pulls(state="all", sort="updated", direction="desc")[:10]

        logging.info(f"Processing PRs from {repo.full_name}")

        for pr in recent_prs:
            logging.debug(f"Evaluating PR #{pr.number}: {pr.title}")
            score = calculate_security_relevance_score(pr, security_keywords, cve_id)

            # Only include PRs with some relevance
            if score > 0:
                logging.info(
                    f"Found relevant PR #{pr.number} with score {score}: {pr.title}"
                )
                prs.append(
                    {
                        "title": pr.title,
                        "url": pr.html_url,
                        "score": score,
                        "repo": repo.full_name,
                        "number": pr.number,
                        "state": pr.state,
                        "merged": pr.merged if pr.state == "closed" else None,
                    }
                )

    except Exception as e:
        logging.error(f"Error searching PRs in {repo.full_name}: {e}")
        print(f"         ⚠️  Error searching PRs in {repo.full_name}: {e}")

    return prs


def search_security_commits(
    github_client: Github,
    repo_names: List[str],
    cve_id: Optional[str],
    package_name: str,
) -> List[Dict[str, Any]]:
    """
    Search for commits that look like security fixes in the given repositories.

    Args:
        github_client: GitHub API client
        repo_names: List of repository names/search terms
        cve_id: CVE ID to search for (if available)
        package_name: Name of the affected package

    Returns:
        List of commit information dictionaries
    """
    security_commits = []

    for repo_name in repo_names:
        try:
            # Try to find the repository
            repo = find_repository(github_client, repo_name)
            if not repo:
                continue

            logging.info(f"Searching commits in {repo.full_name}")

            # Search for commits with security-related content
            commits = search_commits_in_repo(repo, SECURITY_KEYWORDS, cve_id)
            security_commits.extend(commits)

        except Exception as e:
            logging.error(f"Error searching commits in {repo_name}: {e}")
            continue

    # Sort by relevance score (highest first)
    security_commits.sort(key=lambda x: x["score"], reverse=True)

    return security_commits[:3]  # Return top 3 most relevant commits


def search_commits_in_repo(
    repo: Repository, security_keywords: List[str], cve_id: Optional[str]
) -> List[Dict[str, Any]]:
    """
    Search for security-related commits in a specific repository.

    Args:
        repo: Repository to search
        security_keywords: List of security-related keywords
        cve_id: CVE ID to search for

    Returns:
        List of commit information dictionaries
    """
    commits = []

    try:
        # Get recent commits (last 50 to catch more fixes)
        recent_commits = repo.get_commits()[:50]

        logging.info(f"Processing commits from {repo.full_name}")

        for commit in recent_commits:
            score = calculate_commit_security_relevance_score(
                commit, security_keywords, cve_id
            )

            # Only include commits with some relevance
            if score > 0:
                short_msg = commit.commit.message[:50]
                sha = commit.sha[:8]
                logging.info(
                    f"Found relevant commit {sha} with score {score}: {short_msg}..."
                )
                commits.append(
                    {
                        "message": commit.commit.message.split("\n")[
                            0
                        ],  # First line only
                        "url": commit.html_url,
                        "score": score,
                        "repo": repo.full_name,
                        "sha": commit.sha,
                        "date": commit.commit.author.date.strftime("%Y-%m-%d"),
                    }
                )

    except Exception as e:
        logging.error(f"Error searching commits in {repo.full_name}: {e}")

    return commits
