"""
Package to repository mapping functionality.

Maps package names from different ecosystems to potential GitHub repository names.
"""

from typing import List


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
