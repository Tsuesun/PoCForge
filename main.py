#!/usr/bin/env python3
"""
Simple GitHub CVE Fetcher using PyGithub with uv
Run with: uv run main.py
"""

import logging
import os
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from typing import Optional

from github import Github

from cve_tracker import (
    get_potential_repos,
    search_security_commits,
    search_security_prs,
)

# Set up logging (enable ERROR and WARNING for debugging)
logging.basicConfig(
    level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s"
)


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
                            g,
                            potential_repos,
                            advisory.cve_id,
                            pkg.name,
                            advisory.published_at,
                            advisory.summary,
                        )
                        security_commits = search_security_commits(
                            g,
                            potential_repos,
                            advisory.cve_id,
                            pkg.name,
                            advisory.published_at,
                            advisory.summary,
                        )

                        total_found = len(security_prs) + len(security_commits)

                        if total_found > 0:
                            print(
                                f"   ✅ Found {total_found} potential security fixes:"
                            )

                            # Show commits first (often more direct fixes)
                            for commit_info in security_commits:
                                score = commit_info["score"]
                                message = commit_info["message"]
                                print(f"      🔧 {message} (Score: {score})")
                                print(f"         📄 {commit_info['url']}")
                                print(f"         🏢 {commit_info['repo']}")
                                print(f"         📅 {commit_info['date']}")

                            # Then show PRs
                            for pr_info in security_prs:
                                state_icon = (
                                    "🟢" if pr_info["state"] == "open" else "🔴"
                                )
                                score = pr_info["score"]
                                title = pr_info["title"]
                                print(f"      {state_icon} {title} (Score: {score})")
                                print(f"         📄 {pr_info['url']}")
                                print(f"         🏢 {pr_info['repo']}")
                        else:
                            print("   ❌ No security-related PRs or commits found")

                print("\n" + "=" * 80)

                # Limit output for manageable processing
                if count >= 5:
                    print("(Showing first 5 results...)")
                    break
            else:
                # Since advisories are sorted by published date (newest first),
                # once we hit an old one, we can stop
                break

        print(f"\nFound {count} recent CVEs")

    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Full error details: {e}", exc_info=True)
        import traceback

        traceback.print_exc()
    finally:
        # Explicitly close the connection
        with suppress(AttributeError):
            g.close()


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
