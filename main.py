#!/usr/bin/env python3
"""
Simple GitHub CVE Fetcher using PyGithub with uv
Run with: uv run main.py
"""

import os
import logging
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from github import Github
from github.Repository import Repository
from github.PullRequest import PullRequest

# Set up logging (disabled for cleaner output)
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')


def fetch_recent_cves(token: Optional[str] = None, hours: int = 24) -> None:
    """
    Fetch and print CVEs from the last N hours using PyGithub.

    Args:
        token: GitHub personal access token (optional)
        hours: Hours to look back (default: 24)
    """
    # Calculate date threshold (timezone-aware)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Initialize GitHub client
    g = Github(token) if token else Github()

    try:
        # Get security advisories
        logging.info("Fetching global advisories from GitHub...")
        advisories = g.get_global_advisories()

        print(f"Fetching CVEs from the last {hours} hours...")
        print("=" * 60)

        count = 0
        for advisory in advisories:
            # Check if published recently
            if advisory.published_at and advisory.published_at >= since:
                count += 1

                print(f"\n🚨 CVE: {advisory.cve_id or 'N/A'}")
                print(f"📝 Summary: {advisory.summary}")
                print(f"⚠️  Severity: {advisory.severity.upper()}")
                print(f"📅 Published: {advisory.published_at}")

                # Focus on affected packages for PR correlation
                if advisory.vulnerabilities:
                    for vuln in advisory.vulnerabilities:
                        pkg = vuln.package
                        print(f"\n📦 Package: {pkg.name} ({pkg.ecosystem})")
                        print(f"   Vulnerable: {vuln.vulnerable_version_range}")
                        print(f"   Patched: {vuln.patched_versions}")

                        if not (pkg.name and pkg.ecosystem):
                            continue

                        # Search for PRs
                        potential_repos = get_potential_repos(pkg.name, pkg.ecosystem)
                        if not potential_repos:
                            print("   ❌ No potential repositories found")
                            continue

                        # Search for security fix PRs and commits
                        security_prs = search_security_prs(
                            g, potential_repos, advisory.cve_id, pkg.name
                        )
                        security_commits = search_security_commits(
                            g, potential_repos, advisory.cve_id, pkg.name
                        )
                        
                        total_found = len(security_prs) + len(security_commits)
                        
                        if total_found > 0:
                            print(f"   ✅ Found {total_found} potential security fixes:")
                            
                            # Show commits first (often more direct fixes)
                            for commit_info in security_commits:
                                print(f"      🔧 {commit_info['message']} (Score: {commit_info['score']})")
                                print(f"         📄 {commit_info['url']}")
                                print(f"         🏢 {commit_info['repo']}")
                                print(f"         📅 {commit_info['date']}")
                            
                            # Then show PRs
                            for pr_info in security_prs:
                                state_icon = "🟢" if pr_info['state'] == 'open' else "🔴"
                                print(f"      {state_icon} {pr_info['title']} (Score: {pr_info['score']})")
                                print(f"         📄 {pr_info['url']}")
                                print(f"         🏢 {pr_info['repo']}")
                        else:
                            print("   ❌ No security-related PRs or commits found")

                print("\n" + "=" * 80)

                # Limit output for PoC
                if count >= 10:
                    print("(Showing first 10 results...)")
                    break
            else:
                # Since advisories are sorted by published date (newest first),
                # once we hit an old one, we can stop
                break

        print(f"\nFound {count} recent CVEs")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Explicitly close the connection
        with suppress(AttributeError):
            g.close()


def get_potential_repos(package_name: str, ecosystem: str) -> List[str]:
    """
    Generate potential repository names/search terms based on package info.

    Args:
        package_name: Name of the affected package
        ecosystem: Package ecosystem (npm, pypi, etc.)

    Returns:
        List of potential repository search terms
    """
    potential_repos = []

    # Common patterns for different ecosystems
    if ecosystem.lower() == "npm":
        # npm packages often match repo names
        potential_repos.append(package_name)
        # Some npm packages have org prefixes
        if "/" in package_name:
            org, name = package_name.split("/", 1)
            potential_repos.append(f"{org}/{name}")

    elif ecosystem.lower() == "pypi":
        # Python packages often have different repo names
        potential_repos.append(package_name)
        # Common variations
        potential_repos.append(package_name.replace("-", "_"))
        potential_repos.append(package_name.replace("_", "-"))

    elif ecosystem.lower() in ["maven", "gradle"]:
        # Java packages often follow group:artifact pattern
        if ":" in package_name:
            parts = package_name.split(":")
            potential_repos.append(parts[-1])  # artifact name

    elif ecosystem.lower() == "nuget":
        # .NET packages
        potential_repos.append(package_name)

    else:
        # Generic fallback
        potential_repos.append(package_name)

    return potential_repos[:3]  # Limit to avoid too many searches


def search_security_prs(
    github_client: Github, 
    repo_names: List[str], 
    cve_id: Optional[str], 
    package_name: str
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
    
    # Security-related keywords to search for
    security_keywords = [
        "security", "vulnerability", "CVE", "fix", "patch", "exploit",
        "XSS", "SQL injection", "CSRF", "authentication", "authorization",
        "sanitize", "validate", "escape", "buffer overflow", "DoS", "redos",
        "privilege escalation", "code injection", "path traversal", "regex"
    ]
    
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
            prs = search_prs_in_repo(repo, security_keywords, cve_id)
            security_prs.extend(prs)
            logging.info(f"Found {len(prs)} relevant PRs in {repo.full_name}")
            
        except Exception as e:
            logging.error(f"Error searching {repo_name}: {e}")
            print(f"       ⚠️  Error searching {repo_name}: {e}")
            continue
    
    # Sort by relevance score (highest first)
    security_prs.sort(key=lambda x: x['score'], reverse=True)
    
    return security_prs[:5]  # Return top 5 most relevant PRs


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
            query=f"{repo_name} in:name",
            sort="stars",
            order="desc"
        )
        
        # Return the first (most starred) matching repository
        for repo in repos:
            if repo.name.lower() == repo_name.lower():
                return repo
        
        # If no exact match, return the first result
        if repos.totalCount > 0:
            return repos[0]
            
    except Exception:
        pass
    
    return None


def search_prs_in_repo(
    repo: Repository, 
    security_keywords: List[str], 
    cve_id: Optional[str]
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
        recent_prs = repo.get_pulls(
            state="all",
            sort="updated",
            direction="desc"
        )[:10]
        
        logging.info(f"Processing PRs from {repo.full_name}")
        
        for pr in recent_prs:
            logging.debug(f"Evaluating PR #{pr.number}: {pr.title}")
            score = calculate_security_relevance_score(
                pr, security_keywords, cve_id
            )
            
            # Only include PRs with some relevance
            if score > 0:
                logging.info(f"Found relevant PR #{pr.number} with score {score}: {pr.title}")
                prs.append({
                    'title': pr.title,
                    'url': pr.html_url,
                    'score': score,
                    'repo': repo.full_name,
                    'number': pr.number,
                    'state': pr.state,
                    'merged': pr.merged if pr.state == 'closed' else None
                })
                
    except Exception as e:
        logging.error(f"Error searching PRs in {repo.full_name}: {e}")
        print(f"         ⚠️  Error searching PRs in {repo.full_name}: {e}")
    
    return prs


def calculate_security_relevance_score(
    pr: PullRequest, 
    security_keywords: List[str], 
    cve_id: Optional[str]
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
    if "fix" in search_text and any(word in search_text for word in ["security", "vulnerability", "CVE"]):
        score += 3  # "fix" + security terms
    
    if pr.title.lower().startswith(("fix", "security", "patch")):
        score += 2  # Title starts with fix/security/patch
    
    return score


def search_security_commits(
    github_client: Github, 
    repo_names: List[str], 
    cve_id: Optional[str], 
    package_name: str
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
    
    # Security-related keywords to search for
    security_keywords = [
        "security", "vulnerability", "CVE", "fix", "patch", "exploit",
        "XSS", "SQL injection", "CSRF", "authentication", "authorization",
        "sanitize", "validate", "escape", "buffer overflow", "DoS", "redos",
        "privilege escalation", "code injection", "path traversal", "regex"
    ]
    
    for repo_name in repo_names:
        try:
            # Try to find the repository
            repo = find_repository(github_client, repo_name)
            if not repo:
                continue
                
            logging.info(f"Searching commits in {repo.full_name}")
            
            # Search for commits with security-related content
            commits = search_commits_in_repo(repo, security_keywords, cve_id)
            security_commits.extend(commits)
            
        except Exception as e:
            logging.error(f"Error searching commits in {repo_name}: {e}")
            continue
    
    # Sort by relevance score (highest first)
    security_commits.sort(key=lambda x: x['score'], reverse=True)
    
    return security_commits[:3]  # Return top 3 most relevant commits


def search_commits_in_repo(
    repo: Repository, 
    security_keywords: List[str], 
    cve_id: Optional[str]
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
                logging.info(f"Found relevant commit {commit.sha[:8]} with score {score}: {commit.commit.message[:50]}...")
                commits.append({
                    'message': commit.commit.message.split('\n')[0],  # First line only
                    'url': commit.html_url,
                    'score': score,
                    'repo': repo.full_name,
                    'sha': commit.sha,
                    'date': commit.commit.author.date.strftime('%Y-%m-%d')
                })
                
    except Exception as e:
        logging.error(f"Error searching commits in {repo.full_name}: {e}")
    
    return commits


def calculate_commit_security_relevance_score(
    commit, 
    security_keywords: List[str], 
    cve_id: Optional[str]
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
    if "fix" in search_text and any(word in search_text for word in ["security", "vulnerability", "CVE", "redos"]):
        score += 3  # "fix" + security terms
    
    if search_text.startswith(("fix", "security", "patch")):
        score += 2  # Message starts with fix/security/patch
    
    return score


def main() -> None:
    """Main function"""
    print("Simple GitHub CVE Fetcher")

    # Get token from environment variable
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("Tip: Set GITHUB_TOKEN environment variable for higher rate limits")
        logging.warning("No GITHUB_TOKEN found - using unauthenticated requests")
    else:
        logging.info(f"Using GITHUB_TOKEN (starts with: {token[:8]}...)")

    fetch_recent_cves(token, hours=24)


if __name__ == "__main__":
    main()
