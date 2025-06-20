#!/usr/bin/env python3
"""
Simple GitHub CVE Fetcher using PyGithub with uv
Run with: uv run main.py
"""

from github import Github
from datetime import datetime, timedelta, timezone
import os
from contextlib import suppress
from typing import Optional

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
        advisories = g.get_global_advisories()
        
        print(f"Fetching CVEs from the last {hours} hours...")
        print("=" * 60)
        
        count = 0
        for advisory in advisories:
            # Check if published recently
            if advisory.published_at and advisory.published_at >= since:
                count += 1
                
                print(f"CVE ID: {advisory.cve_id or 'N/A'}")
                print(f"GHSA ID: {advisory.ghsa_id}")
                print(f"Summary: {advisory.summary}")
                print(f"Severity: {advisory.severity}")
                print(f"Published: {advisory.published_at}")
                
                # Focus on affected packages for PR correlation
                if advisory.vulnerabilities:
                    print("🎯 Affected packages (targets for PR search):")
                    for vuln in advisory.vulnerabilities:
                        pkg = vuln.package
                        print(f"  📦 {pkg.name} ({pkg.ecosystem})")
                        print(f"     Vulnerable: {vuln.vulnerable_version_range}")
                        print(f"     Patched: {vuln.patched_versions}")
                        
                        # This is where we'll search for PRs
                        potential_repos = get_potential_repos(pkg.name, pkg.ecosystem)
                        if potential_repos:
                            print(f"     🔍 Potential repos to search: {', '.join(potential_repos)}")
                
                print("-" * 40)
                
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


def get_potential_repos(package_name: str, ecosystem: str) -> list[str]:
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

def main() -> None:
    """Main function"""
    print("Simple GitHub CVE Fetcher")
    
    # Get token from environment variable
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("Tip: Set GITHUB_TOKEN environment variable for higher rate limits")
    
    fetch_recent_cves(token, hours=24)

if __name__ == "__main__":
    main()