"""Data structure creation helpers for PoCForge.

Contains functions to create standardized data structures for CVEs, packages,
commits, and PoCs to reduce code duplication in main.py.
"""

from typing import Any, Dict, Optional


def create_cve_data(advisory: Any) -> Dict[str, Any]:
    """Create standardized CVE data structure from GitHub advisory.

    Args:
        advisory: GitHub Security Advisory object

    Returns:
        Dictionary containing CVE information
    """
    return {
        "cve_id": advisory.cve_id or "N/A",
        "summary": advisory.summary,
        "severity": advisory.severity.upper() if advisory.severity else "UNKNOWN",
        "published_at": advisory.published_at.isoformat() if advisory.published_at else None,
        "advisory_url": advisory.html_url,
        "packages": [],
        "pocs_generated": 0,
    }


def create_package_data(pkg: Any, vuln: Any) -> Dict[str, Any]:
    """Create standardized package data structure from vulnerability info.

    Args:
        pkg: Package object from GitHub advisory
        vuln: Vulnerability object from GitHub advisory

    Returns:
        Dictionary containing package vulnerability information
    """
    return {
        "name": pkg.name or "unknown",
        "ecosystem": pkg.ecosystem or "unknown",
        "vulnerable_versions": vuln.vulnerable_version_range or "unknown",
        "patched_versions": vuln.patched_versions or "unknown",
        "commits": [],
        "pocs": [],
    }


def create_commit_data(commit_info: Dict[str, Any]) -> Dict[str, Any]:
    """Create standardized commit data structure from commit info.

    Args:
        commit_info: Dictionary containing commit information

    Returns:
        Dictionary containing commit data for storage
    """
    return {
        "url": commit_info["url"],
        "sha": commit_info["sha"],
        "message": commit_info["message"],
        "repo": commit_info["repo"],
        "date": commit_info["date"],
    }


def create_poc_data(commit_info: Dict[str, Any], poc_data: Dict[str, Any], diff_size: int, max_diff_size: int) -> Dict[str, Any]:
    """Create standardized PoC data structure from generated PoC info.

    Args:
        commit_info: Dictionary containing commit information
        poc_data: Dictionary containing generated PoC data
        diff_size: Size of the diff that was processed
        max_diff_size: Maximum diff size before switching to git extraction

    Returns:
        Dictionary containing PoC data for storage
    """
    return {
        "commit_url": commit_info["url"],
        "commit_sha": commit_info["sha"],
        "vulnerable_function": poc_data.get("vulnerable_function"),
        "function_signature": poc_data.get("function_signature"),
        "risk_factors": poc_data.get("risk_factors", []),
        "attack_surface": poc_data.get("attack_surface", []),
        "attack_vector": poc_data.get("attack_vector"),
        "vulnerable_code": poc_data.get("vulnerable_code"),
        "fixed_code": poc_data.get("fixed_code"),
        "test_case": poc_data.get("test_case"),
        "prerequisites": poc_data.get("prerequisites"),
        "reasoning": poc_data.get("reasoning"),
        "method": "git_extraction" if diff_size > max_diff_size else "direct",
    }


def create_results_structure(hours: int, target_cve: Optional[str], timestamp: str) -> Dict[str, Any]:
    """Create standardized results structure for JSON output.

    Args:
        hours: Number of hours to look back
        target_cve: Specific CVE ID being targeted (if any)
        timestamp: ISO timestamp of when search was initiated

    Returns:
        Dictionary containing results structure for JSON output
    """
    return {
        "search_params": {"hours": hours, "target_cve": target_cve, "timestamp": timestamp},
        "cves": [],
        "summary": {},
    }


def create_summary_data(total_cves: int, total_packages: int, pocs_generated: int) -> Dict[str, Any]:
    """Create standardized summary data structure.

    Args:
        total_cves: Total number of CVEs processed
        total_packages: Total number of packages analyzed
        pocs_generated: Total number of PoCs successfully generated

    Returns:
        Dictionary containing summary statistics
    """
    success_rate = (pocs_generated / total_packages * 100) if total_packages > 0 else 0

    return {
        "total_cves": total_cves,
        "total_packages": total_packages,
        "pocs_generated": pocs_generated,
        "success_rate": success_rate,
    }
