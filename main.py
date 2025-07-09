#!/usr/bin/env python3
"""
PoCForge - CVE-to-PoC Generator using PyGithub with uv
Run with: uv run main.py
"""

import logging
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from typing import Optional

from github import Github

from cve_tracker import extract_commits_from_advisory_references
from cve_tracker.config import get_anthropic_api_key, get_github_token
from cve_tracker.poc_generator import generate_poc_from_fix_commit

# Set up logging (WARNING level for clean output)
logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")


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
        print("🧪 PoCForge: Creating vulnerability demonstrations from fix commits")
        print("=" * 60)

        count = 0
        total_packages = 0
        poc_generated_count = 0
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

                        # Extract fix commits from advisory references
                        advisory_commits = extract_commits_from_advisory_references(advisory.references)

                        total_packages += 1

                        if advisory_commits:
                            print(f"   ✅ Found {len(advisory_commits)} fix commits from security advisory:")

                            for commit_info in advisory_commits:
                                message = commit_info["message"]
                                print(f"      🔧 {message}")
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
                                        for file in commit_files[:5]:  # Limit to 5 files
                                            if hasattr(file, "patch") and file.patch:
                                                patches.append(f"File: {file.filename}\n{file.patch}")

                                        if patches:
                                            combined_diff = "\n\n".join(patches)

                                            # Log diff size for debugging
                                            diff_size = len(combined_diff)
                                            if diff_size > 12000:
                                                logging.info(f"Large diff detected ({diff_size} chars) - will truncate intelligently")

                                            # Generate PoC
                                            package_info = {
                                                "name": pkg.name or "unknown",
                                                "ecosystem": pkg.ecosystem or "unknown",
                                                "vulnerable_versions": vuln.vulnerable_version_range or "unknown",
                                            }

                                            poc_data = generate_poc_from_fix_commit(
                                                combined_diff,
                                                advisory.summary,
                                                advisory.cve_id or "Unknown",
                                                package_info,
                                                repo_url=commit_info["repo"],
                                                commit_sha=commit_info["sha"],
                                            )

                                            if poc_data["success"]:
                                                poc_generated_count += 1
                                                method_note = ""
                                                if diff_size > 12000:
                                                    method_note = " (using git extraction)"
                                                print(f"         🧪 Generated PoC{method_note}:")
                                                if poc_data["vulnerable_function"]:
                                                    print(f"            🎯 Vulnerable: {poc_data['vulnerable_function']}")
                                                if poc_data["prerequisites"]:
                                                    prereqs = ", ".join(poc_data["prerequisites"][:3])
                                                    print(f"            📋 Prerequisites: {prereqs}")
                                                if poc_data["attack_vector"]:
                                                    print(f"            💥 Attack: {poc_data['attack_vector']}")
                                                if poc_data["vulnerable_code"]:
                                                    print("            🐛 Vulnerable Code:")
                                                    print(f"               {poc_data['vulnerable_code']}")
                                                if poc_data["fixed_code"]:
                                                    print("            ✅ Fixed Code:")
                                                    print(f"               {poc_data['fixed_code']}")
                                                if poc_data["test_case"]:
                                                    print("            🧪 Test Case:")
                                                    print(f"               {poc_data['test_case']}")
                                                if poc_data["reasoning"]:
                                                    print("            💡 Reasoning:")
                                                    print(f"               {poc_data['reasoning']}")
                                            else:
                                                reason = poc_data["reasoning"][:50]
                                                print(f"         ⚠️  PoC generation failed: {reason}")

                                except Exception as e:
                                    print(f"         ⚠️  PoC generation error: {str(e)[:50]}")
                        else:
                            print("   ❌ No fix commits found in advisory references")

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
        print("📊 PoC Generation Summary:")
        print(f"   Total packages analyzed: {total_packages}")
        print(f"   🧪 PoCs generated: {poc_generated_count}")
        if total_packages > 0:
            success_rate = (poc_generated_count / total_packages) * 100
            print(f"   📈 PoC generation rate: {success_rate:.1f}%")

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
    print("PoCForge - CVE-to-PoC Generator")

    # Get tokens from config
    token = get_github_token()
    anthropic_key = get_anthropic_api_key()

    if not token:
        print("Tip: Add GitHub token to config.json for higher rate limits")
        logging.warning("No GITHUB_TOKEN found - using unauthenticated requests")
    else:
        logging.info(f"Using GITHUB_TOKEN from config (starts with: {token[:8]}...)")

    if not anthropic_key:
        print("Warning: No Anthropic API key found - PoC generation will be disabled")
        print("Add your key to config.json or set ANTHROPIC_API_KEY environment variable")
    else:
        logging.info("Using Anthropic API key from config")

    fetch_recent_cves(token, hours=24)  # Back to 24 hours for testing


if __name__ == "__main__":
    main()
