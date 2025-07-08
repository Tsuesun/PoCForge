"""
GitHub repository search and discovery functionality.

Handles finding repositories and searching for security-related PRs and commits.
"""

import logging
from datetime import timedelta
from typing import Any, Dict, List, Optional

from github import Github
from github.Repository import Repository

import re

from .claude_analysis import screen_commits_with_claude
from .security_scoring import (
    SECURITY_KEYWORDS,
    calculate_commit_security_relevance_score,
    calculate_security_relevance_score,
)


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
    commit_pattern = r"https://github\.com/([^/]+/[^/]+)/commit/([a-f0-9]{40})"

    for ref in references:
        match = re.match(commit_pattern, ref)
        if match:
            repo_name = match.group(1)
            commit_sha = match.group(2)
            commits.append(
                {
                    "message": "Fix commit referenced in security advisory",
                    "url": ref,
                    "score": 100,  # Very high confidence - directly from advisory
                    "repo": repo_name,
                    "sha": commit_sha,
                    "date": "Referenced in advisory",
                    "source": "advisory_reference",
                }
            )
            logging.info(
                f"Found advisory-referenced commit: {commit_sha[:8]} in {repo_name}"
            )

    return commits


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
    cve_published_date: Optional[Any] = None,
    cve_description: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Search for PRs that look like security fixes in the given repositories.

    Args:
        github_client: GitHub API client
        repo_names: List of repository names/search terms
        cve_id: CVE ID to search for (if available)
        package_name: Name of the affected package
        cve_published_date: CVE publication date for date-based filtering
        cve_description: CVE description for AI-powered analysis

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
            prs = search_prs_in_repo(
                repo, SECURITY_KEYWORDS, cve_id, cve_published_date, cve_description
            )
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
    repo: Repository,
    security_keywords: List[str],
    cve_id: Optional[str],
    cve_published_date: Optional[Any] = None,
    cve_description: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Search for security-related PRs in a specific repository.

    Args:
        repo: Repository to search
        security_keywords: List of security-related keywords
        cve_id: CVE ID to search for
        cve_published_date: CVE publication date for filtering PRs
        cve_description: CVE description for AI-powered analysis

    Returns:
        List of PR information dictionaries
    """
    prs = []

    try:
        logging.info(f"Getting PRs from {repo.full_name}")

        # Calculate date range for PR search
        if cve_published_date:
            # Search ±30 days around CVE publication
            start_date = cve_published_date - timedelta(days=30)
            end_date = cve_published_date + timedelta(days=30)
            logging.info(
                f"Searching PRs between {start_date.date()} and {end_date.date()}"
            )
            # Increase search window for date-filtered searches
            pr_limit = 50
        else:
            # Fallback to recent PRs if no date available
            logging.info("No CVE date available, searching recent PRs")
            start_date = None
            end_date = None
            pr_limit = 10

        # Get PRs sorted by updated date
        all_prs = repo.get_pulls(state="all", sort="updated", direction="desc")

        # Filter PRs by date if we have CVE publication date
        recent_prs: List[Any] = []
        for pr in all_prs:
            if len(recent_prs) >= pr_limit:
                break

            # Date filtering: check if PR was created/updated in our window
            if start_date and end_date:
                pr_created = pr.created_at
                pr_updated = pr.updated_at

                # Include PR if it was created or updated within our date window
                if not (
                    (start_date <= pr_created <= end_date)
                    or (start_date <= pr_updated <= end_date)
                ):
                    continue

            recent_prs.append(pr)

        logging.info(f"Processing {len(recent_prs)} PRs from {repo.full_name}")

        for pr in recent_prs:
            logging.debug(f"Evaluating PR #{pr.number}: {pr.title}")
            score = calculate_security_relevance_score(
                pr, security_keywords, cve_id, cve_description
            )

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
    cve_published_date: Optional[Any] = None,
    cve_description: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Search for commits that look like security fixes in the given repositories.

    Args:
        github_client: GitHub API client
        repo_names: List of repository names/search terms
        cve_id: CVE ID to search for (if available)
        package_name: Name of the affected package
        cve_published_date: CVE publication date for date-based filtering
        cve_description: CVE description for AI-powered analysis

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
            commits = search_commits_in_repo(
                repo, SECURITY_KEYWORDS, cve_id, cve_published_date, cve_description
            )
            security_commits.extend(commits)

        except Exception as e:
            logging.error(f"Error searching commits in {repo_name}: {e}")
            continue

    # Sort by relevance score (highest first)
    security_commits.sort(key=lambda x: x["score"], reverse=True)

    return security_commits[:3]  # Return top 3 most relevant commits


def search_commits_in_repo(
    repo: Repository,
    security_keywords: List[str],
    cve_id: Optional[str],
    cve_published_date: Optional[Any] = None,
    cve_description: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Search for security-related commits in a specific repository.

    Args:
        repo: Repository to search
        security_keywords: List of security-related keywords
        cve_id: CVE ID to search for
        cve_published_date: CVE publication date for filtering commits
        cve_description: CVE description for AI-powered analysis

    Returns:
        List of commit information dictionaries
    """
    commits = []

    try:
        logging.info(f"Getting commits from {repo.full_name}")

        # Calculate date range for commit search
        if cve_published_date:
            # Search ±30 days around CVE publication
            start_date = cve_published_date - timedelta(days=30)
            end_date = cve_published_date + timedelta(days=30)
            logging.info(
                f"Searching commits between {start_date.date()} and {end_date.date()}"
            )
            # Increase search window for date-filtered searches
            commit_limit = 30  # Reduce for faster Claude processing
        else:
            # Fallback to recent commits if no date available
            logging.info("No CVE date available, searching recent commits")
            start_date = None
            end_date = None
            commit_limit = 20  # Reduce for faster processing

        # Get commits sorted by commit date
        all_commits = repo.get_commits()

        # Filter commits by date if we have CVE publication date
        recent_commits: List[Any] = []
        for commit in all_commits:
            if len(recent_commits) >= commit_limit:
                break

            # Date filtering: check if commit was created within our window
            if start_date and end_date:
                commit_date = commit.commit.author.date

                # Include commit if it was created within our date window
                if not (start_date <= commit_date <= end_date):
                    continue

            recent_commits.append(commit)

        logging.info(f"Processing {len(recent_commits)} commits from {repo.full_name}")

        # Step 1: AI-first screening of all commits
        if cve_description and recent_commits:
            # Prepare data for screening (just message and SHA)
            screening_data = []
            for commit in recent_commits:
                screening_data.append(
                    {"sha": commit.sha, "message": commit.commit.message}
                )

            # Get AI screening scores
            screening_scores = screen_commits_with_claude(
                screening_data, cve_description, cve_id
            )

            # Step 2: Detailed analysis only for AI-selected commits
            for commit in recent_commits:
                screening_score = screening_scores.get(commit.sha, 0)
                short_msg = commit.commit.message[:50]
                sha = commit.sha[:8]

                # Debug: Log all screening scores
                if screening_score > 0:
                    logging.info(
                        f"AI screening for {sha}: score={screening_score}, msg='{short_msg}'"
                    )

                # Only do detailed analysis if AI thinks it's promising
                if screening_score > 0:
                    detailed_score = calculate_commit_security_relevance_score(
                        commit, security_keywords, cve_id, cve_description
                    )

                    # Combine AI screening with detailed analysis
                    final_score = detailed_score + screening_score

                    if final_score > 0:
                        logging.info(
                            f"Found relevant commit {sha} with score {final_score} "
                            f"(s: {screening_score}, d: {detailed_score}): "
                            f"{short_msg}..."
                        )
                        commits.append(
                            {
                                "message": commit.commit.message.split("\n")[
                                    0
                                ],  # First line only
                                "url": commit.html_url,
                                "score": final_score,
                                "repo": repo.full_name,
                                "sha": commit.sha,
                                "date": commit.commit.author.date.strftime("%Y-%m-%d"),
                            }
                        )
        else:
            # Fallback to keyword-first analysis if no CVE description
            for commit in recent_commits:
                score = calculate_commit_security_relevance_score(
                    commit, security_keywords, cve_id, cve_description
                )

                # Only include commits with some relevance
                if score > 0:
                    short_msg = commit.commit.message[:50]
                    sha = commit.sha[:8]
                    logging.info(
                        f"Found relevant commit {sha} with score {score}: "
                        f"{short_msg}..."
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
