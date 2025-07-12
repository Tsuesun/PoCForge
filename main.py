#!/usr/bin/env python3
"""
PoCForge - CVE-to-PoC Generator using PyGithub with uv
Run with: uv run main.py
"""

import json
import logging
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import typer
from github import Github

from cve_tracker import extract_commits_from_advisory_references
from cve_tracker.config import get_anthropic_api_key, get_github_token
from cve_tracker.constants import (
    DEFAULT_HOURS_LOOKBACK,
    DEFAULT_JSON_INDENT,
    MAX_DIFF_SIZE,
    MAX_DISPLAY_ITEMS,
    MAX_DISPLAY_RESULTS,
    MAX_ERROR_REASON_LENGTH,
    MAX_FILES_TO_PROCESS,
    SEPARATOR_LINE_LENGTH,
    TOKEN_DISPLAY_PREFIX_LENGTH,
)
from cve_tracker.data_structures import (
    create_commit_data,
    create_cve_data,
    create_package_data,
    create_poc_data,
    create_results_structure,
    create_summary_data,
)
from cve_tracker.poc_generator import generate_poc_from_fix_commit

# Set up logging (WARNING level for clean output)
logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")


def fetch_recent_cves(token: Optional[str] = None, hours: int = DEFAULT_HOURS_LOOKBACK, target_cve: Optional[str] = None, json_output: bool = False) -> None:
    """
    Fetch and print CVEs from the last N hours using PyGithub.

    Args:
        token: GitHub personal access token (optional)
        hours: Hours to look back (default: DEFAULT_HOURS_LOOKBACK)
        target_cve: Specific CVE ID to target (e.g., CVE-2024-1234)
        json_output: Output results in JSON format instead of human-readable
    """
    # Collect all output data to display at the end (after logging)
    output_lines = []
    # Calculate date threshold (timezone-aware)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Initialize GitHub client
    g = Github(token) if token else Github()

    # Initialize results structure for JSON output
    results: Dict[str, Any] = create_results_structure(hours, target_cve, datetime.now(timezone.utc).isoformat())

    try:
        if not json_output:
            if target_cve:
                output_lines.append(f"Targeting specific CVE: {target_cve}")
            else:
                output_lines.append(f"Fetching CVEs from the last {hours} hours...")
            output_lines.append("🧪 PoCForge: Creating vulnerability demonstrations from fix commits")
            output_lines.append("=" * SEPARATOR_LINE_LENGTH)

        if target_cve:
            # Direct CVE lookup using GitHub API filtering
            logging.info(f"Searching for specific CVE: {target_cve}")
            try:
                # Use direct CVE ID filtering instead of fetching all advisories
                advisories = g.get_global_advisories(cve_id=target_cve)

                # PyGithub returns a PaginatedList, check if it has any results
                # by accessing the first page
                try:
                    first_page = advisories.get_page(0)
                    if not first_page:
                        if not json_output:
                            output_lines.append(f"❌ CVE {target_cve} not found in GitHub Security Advisories")
                        else:
                            results["error"] = f"CVE {target_cve} not found in GitHub Security Advisories"
                            print(json.dumps(results, indent=DEFAULT_JSON_INDENT))
                        return
                except Exception:
                    if not json_output:
                        output_lines.append(f"❌ CVE {target_cve} not found in GitHub Security Advisories")
                    else:
                        results["error"] = f"CVE {target_cve} not found in GitHub Security Advisories"
                        print(json.dumps(results, indent=DEFAULT_JSON_INDENT))
                    return

            except Exception as e:
                if not json_output:
                    output_lines.append(f"❌ Error searching for CVE {target_cve}: {e}")
                else:
                    results["error"] = f"Error searching for CVE {target_cve}: {e}"
                    print(json.dumps(results, indent=DEFAULT_JSON_INDENT))
                return
        else:
            # Get security advisories for time-based search
            # Note: GitHub API doesn't support time filtering, so we fetch recent ones
            logging.info("Fetching global advisories from GitHub...")
            advisories = g.get_global_advisories()

        count = 0
        total_packages = 0
        poc_generated_count = 0
        for advisory in advisories:
            # For time-based search, check if published recently
            if not target_cve and advisory.published_at and advisory.published_at < since:
                # Since advisories are sorted by published date (newest first),
                # once we hit an old one, we can stop
                break

            count += 1

            # Create CVE data structure
            cve_data: Dict[str, Any] = create_cve_data(advisory)

            if not json_output:
                output_lines.append(f"\n🚨 CVE: {cve_data['cve_id']}")
                output_lines.append(f"📝 Summary: {cve_data['summary']}")
                output_lines.append(f"⚠️  Severity: {cve_data['severity']}")
                output_lines.append(f"📅 Published: {advisory.published_at}")
                output_lines.append(f"🔗 Advisory: {advisory.html_url}")

            # Focus on affected packages for PR correlation
            if advisory.vulnerabilities:
                for vuln in advisory.vulnerabilities:
                    pkg = vuln.package

                    # Create package data structure
                    package_data: Dict[str, Any] = create_package_data(pkg, vuln)

                    if not json_output:
                        output_lines.append(f"\n📦 Package: {package_data['name']} ({package_data['ecosystem']})")
                        output_lines.append(f"   Vulnerable: {package_data['vulnerable_versions']}")
                        output_lines.append(f"   Patched: {package_data['patched_versions']}")

                    if not (pkg.name and pkg.ecosystem):
                        continue

                    # Extract fix commits from advisory references
                    advisory_commits = extract_commits_from_advisory_references(advisory.references)

                    total_packages += 1

                    if advisory_commits:
                        if not json_output:
                            output_lines.append(f"   ✅ Found {len(advisory_commits)} fix commits from security advisory:")

                        for commit_info in advisory_commits:
                            # Add commit info to package data
                            commit_data = create_commit_data(commit_info)
                            package_data["commits"].append(commit_data)

                            if not json_output:
                                message = commit_info["message"]
                                output_lines.append(f"      🔧 {message}")
                                output_lines.append(f"         📄 {commit_info['url']}")
                                output_lines.append(f"         🏢 {commit_info['repo']}")
                                output_lines.append(f"         📅 {commit_info['date']}")

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
                                    # Combine patches from all files, prioritizing code files
                                    patches = []

                                    # Prioritize code files (Python, JS, Java, etc.) over documentation
                                    code_extensions = {
                                        ".py",
                                        ".js",
                                        ".java",
                                        ".rs",
                                        ".go",
                                        ".cpp",
                                        ".c",
                                        ".h",
                                        ".tsx",
                                        ".ts",
                                        ".php",
                                        ".rb",
                                        ".cs",
                                        ".swift",
                                        ".kt",
                                    }
                                    code_files = [f for f in commit_files if any(f.filename.endswith(ext) for ext in code_extensions)]
                                    other_files = [f for f in commit_files if not any(f.filename.endswith(ext) for ext in code_extensions)]

                                    # Process code files first, then other files, but limit to MAX_FILES_TO_PROCESS total
                                    selected_files = (code_files + other_files)[:MAX_FILES_TO_PROCESS]

                                    for file in selected_files:
                                        if hasattr(file, "patch") and file.patch:
                                            patches.append(f"File: {file.filename}\n{file.patch}")

                                    if patches:
                                        combined_diff = "\n\n".join(patches)

                                        # Log diff size for debugging
                                        diff_size = len(combined_diff)
                                        if diff_size > MAX_DIFF_SIZE:
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
                                            if diff_size > MAX_DIFF_SIZE:
                                                method_note = " (using git extraction)"

                                            # Add PoC to package data
                                            package_data["pocs"].append(create_poc_data(commit_info, poc_data, diff_size, MAX_DIFF_SIZE))

                                            if not json_output:
                                                output_lines.append(f"         🧪 Generated PoC{method_note}:")
                                                if poc_data["vulnerable_function"]:
                                                    output_lines.append(f"            🎯 Vulnerable: {poc_data['vulnerable_function']}")
                                                if poc_data.get("function_signature"):
                                                    output_lines.append(f"            📝 Signature: {poc_data['function_signature']}")
                                                # Display risk factors and attack surface
                                                if poc_data.get("risk_factors"):
                                                    risks = ", ".join(poc_data["risk_factors"][:MAX_DISPLAY_ITEMS])
                                                    output_lines.append(f"            ⚠️  Risk Factors: {risks}")
                                                if poc_data.get("attack_surface"):
                                                    surface = ", ".join(poc_data["attack_surface"][:MAX_DISPLAY_ITEMS])
                                                    output_lines.append(f"            🎯 Attack Surface: {surface}")
                                                if poc_data["prerequisites"]:
                                                    prereqs = ", ".join(poc_data["prerequisites"][:MAX_DISPLAY_ITEMS])
                                                    output_lines.append(f"            📋 Prerequisites: {prereqs}")
                                                if poc_data["attack_vector"]:
                                                    output_lines.append(f"            💥 Attack: {poc_data['attack_vector']}")
                                                if poc_data["vulnerable_code"]:
                                                    output_lines.append("            🐛 Vulnerable Code:")
                                                    output_lines.append(f"               {poc_data['vulnerable_code']}")
                                                if poc_data["fixed_code"]:
                                                    output_lines.append("            ✅ Fixed Code:")
                                                    output_lines.append(f"               {poc_data['fixed_code']}")
                                                if poc_data["test_case"]:
                                                    output_lines.append("            🧪 Test Case:")
                                                    output_lines.append(f"               {poc_data['test_case']}")
                                                if poc_data["reasoning"]:
                                                    output_lines.append("            💡 Reasoning:")
                                                    output_lines.append(f"               {poc_data['reasoning']}")
                                        else:
                                            reason = poc_data["reasoning"][:MAX_ERROR_REASON_LENGTH]
                                            if not json_output:
                                                output_lines.append(f"         ⚠️  PoC generation failed: {reason}")

                            except Exception as e:
                                if not json_output:
                                    output_lines.append(f"         ⚠️  PoC generation error: {str(e)[:MAX_ERROR_REASON_LENGTH]}")
                    else:
                        if not json_output:
                            output_lines.append("   ❌ No fix commits found in advisory references")

                    # Add package to CVE data
                    cve_data["packages"].append(package_data)
                    cve_data["pocs_generated"] += len(package_data["pocs"])

            if not json_output:
                output_lines.append("\n" + "=" * SEPARATOR_LINE_LENGTH)

            # Limit output for manageable processing
            if not target_cve and count >= MAX_DISPLAY_RESULTS:
                if not json_output:
                    print(f"(Showing first {MAX_DISPLAY_RESULTS} results...)")
                break

            # Add CVE to results
            results["cves"].append(cve_data)

        # Output results
        results["summary"] = create_summary_data(count, total_packages, poc_generated_count)
        if json_output:
            print(json.dumps(results, indent=DEFAULT_JSON_INDENT))
        else:
            # Store summary for later printing
            output_lines.append(f"\nFound {count} recent CVEs")
            output_lines.append("📊 PoC Generation Summary:")
            output_lines.append(f"   Total packages analyzed: {total_packages}")
            output_lines.append(f"   🧪 PoCs generated: {poc_generated_count}")
            if total_packages > 0:
                success_rate = (poc_generated_count / total_packages) * 100
                output_lines.append(f"   📈 PoC generation rate: {success_rate:.1f}%")

    except Exception as e:
        if not json_output:
            output_lines.append(f"Error: {e}")
        else:
            print(f"Error: {e}")
        logging.error(f"Full error details: {e}", exc_info=True)
        import traceback

        traceback.print_exc()
    finally:
        # Print all collected output after any logging has completed
        if not json_output and output_lines:
            for line in output_lines:
                print(line)

        # Explicitly close the connection
        with suppress(AttributeError):
            g.close()


app = typer.Typer(help="PoCForge - CVE-to-PoC Generator")


@app.command()
def main(
    hours: int = typer.Option(DEFAULT_HOURS_LOOKBACK, "--hours", "-h", help="Hours to look back for recent CVEs"),
    cve: Optional[str] = typer.Option(None, "--cve", "-c", help="Target specific CVE (e.g., CVE-2024-1234)"),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format"),
) -> None:
    """
    PoCForge - Generate Proof-of-Concept demonstrations from CVE fix commits.

    Examples:
        uv run main.py                          # Last 24 hours
        uv run main.py --hours 48               # Last 48 hours
        uv run main.py --cve CVE-2024-1234      # Specific CVE
        uv run main.py --json                   # JSON output
        uv run main.py --cve CVE-2024-1234 --json  # Specific CVE as JSON
    """
    # Always print title immediately for non-JSON output
    if not json_output:
        print("PoCForge - CVE-to-PoC Generator")

    # Get tokens from config
    token = get_github_token()
    anthropic_key = get_anthropic_api_key()

    # Collect warning messages for later display
    warning_messages = []

    if not token:
        if not json_output:
            warning_messages.append("Tip: Add GitHub token to config.json for higher rate limits")
        logging.warning("No GITHUB_TOKEN found - using unauthenticated requests")
    else:
        logging.info(f"Using GITHUB_TOKEN from config (starts with: {token[:TOKEN_DISPLAY_PREFIX_LENGTH]}...)")

    if not anthropic_key:
        if not json_output:
            warning_messages.append("Warning: No Anthropic API key found - PoC generation will be disabled")
            warning_messages.append("Add your key to config.json or set ANTHROPIC_API_KEY environment variable")
    else:
        logging.info("Using Anthropic API key from config")

    # Print warnings after any logging
    for warning in warning_messages:
        print(warning)

    fetch_recent_cves(token, hours=hours, target_cve=cve, json_output=json_output)


if __name__ == "__main__":
    app()
