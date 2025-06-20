#!/usr/bin/env python3

from github import Github
from datetime import datetime, timedelta, timezone
import os

def fetch_recent_cves(token=None, hours=24):
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
        print(f"\nFound {advisories.totalCount} recent CVEs")
        for advisory in advisories:
            # Check if published recently
            if advisory.published_at and advisory.published_at >= since:
                
                print(f"CVE ID: {advisory.cve_id or 'N/A'}")
                print(f"GHSA ID: {advisory.ghsa_id}")
                print(f"Summary: {advisory.summary}")
                print(f"Severity: {advisory.severity}")
                print(f"Published: {advisory.published_at}")
                
                # Show affected packages
                if advisory.vulnerabilities:
                    print("Affected packages:")
                    for vuln in advisory.vulnerabilities:
                        pkg = vuln.package
                        print(f"  - {pkg.name} ({pkg.ecosystem})")

            else:
                break
        
        
        
    except Exception as e:
        print(f"Error: {e}")
    finally:

        # Explicitly close the connection
        try:
            g.close()
        except AttributeError:
            # Some versions might not have close method
            pass

def main():
    """Main function"""
    print("Simple GitHub CVE Fetcher")
    
    # Get token from environment variable
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("Tip: Set GITHUB_TOKEN environment variable for higher rate limits")
    
    fetch_recent_cves(token, hours=24)

if __name__ == "__main__":
    main()
