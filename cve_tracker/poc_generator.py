"""
CVE Proof-of-Concept (PoC) Generator.

Analyzes fix commits to generate vulnerability demonstrations and test cases.
"""

import logging
import os
import re
from typing import Any, Dict

import anthropic


def generate_poc_from_fix_commit(
    commit_diff: str,
    cve_description: str,
    cve_id: str,
    package_info: Dict[str, str],
) -> Dict[str, Any]:
    """
    Generate a Proof-of-Concept from a fix commit diff.

    Args:
        commit_diff: The git diff showing what was fixed
        cve_description: Description of the vulnerability
        cve_id: CVE identifier
        package_info: Package name, ecosystem, vulnerable versions

    Returns:
        Dictionary containing PoC code, prerequisites, and context
    """
    # Initialize default response
    poc_data = {
        "vulnerable_code": None,
        "fixed_code": None,
        "prerequisites": [],
        "vulnerable_function": None,
        "attack_vector": None,
        "test_case": None,
        "reasoning": "No Claude API key available",
        "success": False,
    }

    # Check for API key
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        poc_data["reasoning"] = "No ANTHROPIC_API_KEY environment variable set"
        return poc_data

    # Skip analysis if diff is too large
    if len(commit_diff) > 12000:  # 12KB limit
        poc_data["reasoning"] = "Commit diff too large for PoC generation"
        return poc_data

    try:
        client = anthropic.Anthropic(api_key=api_key)

        # Create the PoC generation prompt
        prompt = f"""Analyze this security fix commit and generate a \
Proof-of-Concept (PoC) demonstration.

CVE: {cve_id}
Vulnerability: {cve_description}
Package: {package_info.get("name", "unknown")} \
({package_info.get("ecosystem", "unknown")})
Vulnerable Versions: {package_info.get("vulnerable_versions", "unknown")}

Fix Commit Diff:
{commit_diff}

Generate a practical PoC that demonstrates the vulnerability. \
Analyze the fix to understand what was vulnerable before.

Return JSON only:
{{
  "vulnerable_function": "function/method name that was vulnerable",
  "prerequisites": ["list", "of", "conditions", "needed", "for", "vulnerability"],
  "attack_vector": "brief description of how the attack works",
  "vulnerable_code": "minimal code example that triggers the vulnerability",
  "fixed_code": "same code but with the fix applied",
  "test_case": "complete test case showing vulnerable vs fixed behavior",
  "reasoning": "explanation of the vulnerability and fix"
}}

Focus on:
1. What specific function/code was vulnerable
2. What conditions must be met to trigger it
3. Minimal reproduction code
4. Clear before/after comparison"""

        response = client.messages.create(
            model="claude-3-sonnet-20241022",  # Use Sonnet for better code generation
            max_tokens=1500,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}],
        )

        # Parse Claude's response
        try:
            import json

            content_block = response.content[0]
            if hasattr(content_block, "text"):
                claude_response = content_block.text.strip()
            else:
                raise ValueError("Unexpected response format from Claude API")

            # Clean markdown formatting
            if claude_response.startswith("```json"):
                claude_response = (
                    claude_response.replace("```json", "").replace("```", "").strip()
                )
            elif claude_response.startswith("```"):
                claude_response = claude_response.replace("```", "").strip()

            poc_result = json.loads(claude_response)

            # Update with parsed results
            poc_data.update(
                {
                    "vulnerable_function": str(
                        poc_result.get("vulnerable_function", "")
                    )[:100],
                    "prerequisites": poc_result.get("prerequisites", [])[
                        :10
                    ],  # Limit to 10 items
                    "attack_vector": str(poc_result.get("attack_vector", ""))[:300],
                    "vulnerable_code": str(poc_result.get("vulnerable_code", ""))[
                        :2000
                    ],
                    "fixed_code": str(poc_result.get("fixed_code", ""))[:2000],
                    "test_case": str(poc_result.get("test_case", ""))[:3000],
                    "reasoning": str(poc_result.get("reasoning", ""))[:500],
                    "success": True,
                }
            )

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logging.warning(f"Failed to parse Claude PoC response: {e}")
            poc_data["reasoning"] = f"PoC parse error: {str(e)[:100]}"

    except Exception as e:
        logging.error(f"PoC generation error: {e}")
        poc_data["reasoning"] = f"PoC generation error: {str(e)[:100]}"

    return poc_data


def extract_vulnerability_context(
    commit_diff: str,
    cve_description: str,
) -> Dict[str, Any]:
    """
    Extract vulnerability context and prerequisites from commit diff.

    Args:
        commit_diff: The git diff showing what was fixed
        cve_description: Description of the vulnerability

    Returns:
        Dictionary with vulnerability context information
    """
    context = {
        "modified_files": [],
        "functions_changed": [],
        "config_changes": [],
        "dependency_changes": [],
    }

    # Extract modified files
    file_pattern = r"diff --git a/(.*?) b/(.*?)(?:\n|$)"
    files = re.findall(file_pattern, commit_diff)
    context["modified_files"] = [f[0] for f in files]

    # Extract function signatures (simplified pattern matching)
    function_patterns = [
        r"def\s+(\w+)\s*\(",  # Python functions
        r"function\s+(\w+)\s*\(",  # JavaScript functions
        r"(\w+)\s*\([^)]*\)\s*{",  # Java/C-style functions
        r"fn\s+(\w+)\s*\(",  # Rust functions
    ]

    functions = set()
    for pattern in function_patterns:
        matches = re.findall(pattern, commit_diff)
        functions.update(matches)

    context["functions_changed"] = list(functions)[:10]  # Limit to 10

    # Look for configuration-related changes
    config_indicators = [
        r"config",
        r"setting",
        r"option",
        r"flag",
        r"enable",
        r"disable",
        r"parameter",
        r"env",
        r"variable",
    ]

    config_changes = []
    for indicator in config_indicators:
        if re.search(indicator, commit_diff, re.IGNORECASE):
            config_changes.append(indicator)

    context["config_changes"] = config_changes[:5]

    return context
