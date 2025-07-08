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
    extract_commits_from_advisory_references,
    get_potential_repos,
    search_security_commits,
    search_security_prs,
)
from cve_tracker.poc_generator import generate_poc_from_fix_commit

# Set up logging (WARNING level for clean output)
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
        print(
            "🧪 CVE-to-PoC Generator: Creating vulnerability demonstrations from fix commits"
        )
        print("=" * 60)

        count = 0
        advisory_reference_count = 0
        total_packages = 0
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

                        # First, check if advisory references contain direct commit links
                        advisory_commits = extract_commits_from_advisory_references(
                            advisory.references
                        )

                        total_packages += 1
                        if advisory_commits:
                            advisory_reference_count += 1

                        # Restructured approach: Advisory-first, AI fallback
                        if advisory_commits:
                            # HIGH CONFIDENCE: Use advisory references (95% of cases)
                            print(
                                f"   ✅ Found {len(advisory_commits)} authoritative fix commits from security advisory:"
                            )

                            # Sort by score (advisory refs have score 100)
                            advisory_commits.sort(
                                key=lambda x: x["score"], reverse=True
                            )
                            for commit_info in advisory_commits:
                                score = commit_info["score"]
                                message = commit_info["message"]
                                print(f"      🔧 {message} (Score: {score})")
                                print(f"         📄 {commit_info['url']}")
                                print(f"         🏢 {commit_info['repo']}")
                                print(f"         📅 {commit_info['date']}")

                                # Generate PoC from fix commit
                                try:
                                    # Extract commit SHA from URL
                                    commit_sha = commit_info["sha"]
                                    repo_name = commit_info["repo"]

                                    # Get the actual commit object to fetch diff
                                    repo_obj = g.get_repo(repo_name)
                                    commit_obj = repo_obj.get_commit(commit_sha)

                                    # Get commit diff
                                    commit_files = list(commit_obj.files)
                                    if commit_files:
                                        # Combine patches from all files
                                        patches = []
                                        for file in commit_files[
                                            :5
                                        ]:  # Limit to 5 files
                                            if hasattr(file, "patch") and file.patch:
                                                patches.append(
                                                    f"File: {file.filename}\n{file.patch}"
                                                )

                                        if patches:
                                            combined_diff = "\n\n".join(patches)

                                            # Generate PoC
                                            package_info = {
                                                "name": pkg.name,
                                                "ecosystem": pkg.ecosystem,
                                                "vulnerable_versions": vuln.vulnerable_version_range,
                                            }

                                            poc_data = generate_poc_from_fix_commit(
                                                combined_diff,
                                                advisory.summary,
                                                advisory.cve_id or "Unknown",
                                                package_info,
                                            )

                                            if poc_data["success"]:
                                                print(f"         🧪 Generated PoC:")
                                                if poc_data["vulnerable_function"]:
                                                    print(
                                                        f"            🎯 Vulnerable: {poc_data['vulnerable_function']}"
                                                    )
                                                if poc_data["prerequisites"]:
                                                    print(
                                                        f"            📋 Prerequisites: {', '.join(poc_data['prerequisites'][:3])}"
                                                    )
                                                if poc_data["attack_vector"]:
                                                    print(
                                                        f"            💥 Attack: {poc_data['attack_vector'][:100]}..."
                                                    )
                                            else:
                                                print(
                                                    f"         ⚠️  PoC generation failed: {poc_data['reasoning'][:50]}"
                                                )

                                except Exception as e:
                                    print(
                                        f"         ⚠️  PoC generation error: {str(e)[:50]}"
                                    )
                        else:
                            # LOW CONFIDENCE: Fallback to AI analysis (5% of cases)
                            print(
                                "   ⚠️  No advisory references found - falling back to AI analysis..."
                            )

                            # Search for PRs
                            potential_repos = get_potential_repos(
                                pkg.name, pkg.ecosystem
                            )
                            if not potential_repos:
                                print("   ❌ No potential repositories found")
                                continue

                            # Search for security fix PRs and commits using AI
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
                                    f"   🔍 Found {total_found} potential security fixes (AI analysis):"
                                )

                                # Show commits first (often more direct fixes)
                                security_commits.sort(
                                    key=lambda x: x["score"], reverse=True
                                )
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
                                    print(
                                        f"      {state_icon} {title} (Score: {score})"
                                    )
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
        print(f"📊 Analysis Summary:")
        print(f"   Total packages analyzed: {total_packages}")
        print(
            f"   ✅ Authoritative fixes (advisory references): {advisory_reference_count}"
        )
        print(
            f"   🔍 AI analysis required: {total_packages - advisory_reference_count}"
        )
        if total_packages > 0:
            coverage = (advisory_reference_count / total_packages) * 100
            ai_savings = coverage
            print(f"   📈 Advisory coverage: {coverage:.1f}%")
            print(f"   💰 AI cost savings: {ai_savings:.1f}%")

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
    print("CVE-to-PoC Generator")

    # Get token from environment variable
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("Tip: Set GITHUB_TOKEN environment variable for higher rate limits")
        logging.warning("No GITHUB_TOKEN found - using unauthenticated requests")
    else:
        logging.info(f"Using GITHUB_TOKEN (starts with: {token[:8]}...)")

    fetch_recent_cves(token, hours=24)  # Back to 24 hours for testing


if __name__ == "__main__":
    main()
