"""
CVE-to-PoC Generator - A tool for generating vulnerability demonstrations from fix commits.
"""

from .github_search import extract_commits_from_advisory_references

__all__ = [
    "extract_commits_from_advisory_references",
]
