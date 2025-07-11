"""
PoCForge - CVE Proof-of-Concept (PoC) Generator.

Analyzes fix commits to generate vulnerability demonstrations and test cases.
"""

import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

import anthropic

from .config import get_anthropic_api_key


def _extract_changed_functions_with_git(repo_url: str, commit_sha: str) -> str:
    """
    Use git to extract only the changed function bodies from a commit.

    Args:
        repo_url: GitHub repository URL (e.g., "owner/repo")
        commit_sha: Commit SHA to analyze

    Returns:
        Focused diff showing only changed function bodies
    """
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "repo"

            # Clone the repository (shallow clone for speed)
            clone_cmd = ["git", "clone", "--depth", "10", f"https://github.com/{repo_url}.git", str(repo_path)]
            subprocess.run(clone_cmd, check=True, capture_output=True)

            # Get function-context diff
            diff_cmd = [
                "git",
                "show",
                "--format=",  # No commit message
                "-W",  # Show whole function context
                "--no-patch-with-stat",  # No stats
                commit_sha,
            ]

            result = subprocess.run(diff_cmd, cwd=repo_path, check=True, capture_output=True, text=True)

            # If still too large, try with minimal context
            if len(result.stdout) > 15000:
                logging.info("Function context still large, using minimal context")
                diff_cmd = [
                    "git",
                    "show",
                    "--format=",  # No commit message
                    "-U3",  # 3 lines of context
                    "--no-patch-with-stat",
                    commit_sha,
                ]

                result = subprocess.run(diff_cmd, cwd=repo_path, check=True, capture_output=True, text=True)

            return result.stdout

    except subprocess.CalledProcessError as e:
        logging.warning(f"Git command failed: {e}")
        return f"[Git extraction failed: {e}]"
    except Exception as e:
        logging.warning(f"Git extraction error: {e}")
        return f"[Git extraction error: {e}]"


def generate_poc_from_fix_commit(
    commit_diff: str,
    cve_description: str,
    cve_id: str,
    package_info: Dict[str, str],
    repo_url: Optional[str] = None,
    commit_sha: Optional[str] = None,
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
    poc_data: Dict[str, Any] = {
        "vulnerable_code": None,
        "fixed_code": None,
        "prerequisites": [],
        "vulnerable_function": None,
        "function_signature": None,
        "risk_factors": [],
        "attack_surface": [],
        "attack_vector": None,
        "test_case": None,
        "reasoning": "No Claude API key available",
        "success": False,
    }

    # Check for API key
    api_key = get_anthropic_api_key()
    if not api_key:
        poc_data["reasoning"] = "No Anthropic API key found in config.json or environment"
        return poc_data

    # Handle large diffs using git extraction
    if len(commit_diff) > 12000:  # 12KB limit
        logging.info(f"Large commit diff ({len(commit_diff)} chars), using git extraction")
        if repo_url and commit_sha:
            git_diff = _extract_changed_functions_with_git(repo_url, commit_sha)
            if not git_diff.startswith("[Git extraction"):
                commit_diff = git_diff
                logging.info(f"Git extraction successful, new size: {len(commit_diff)} chars")
            else:
                logging.warning("Git extraction failed, using original diff truncated")
                commit_diff = commit_diff[:10000] + "\n... [diff truncated due to size]"
        else:
            logging.warning("No repo/commit info for git extraction, truncating diff")
            commit_diff = commit_diff[:10000] + "\n... [diff truncated due to size]"

    try:
        client = anthropic.Anthropic(api_key=api_key)

        # Create the PoC generation prompt
        is_git_extracted = "git show" in commit_diff or len(commit_diff) > 12000
        is_truncated = "[diff truncated" in commit_diff

        context_note = ""
        if is_git_extracted and not is_truncated:
            context_note = "\n\nNOTE: This diff was extracted using git with full function context for better analysis."
        elif is_truncated:
            context_note = "\n\nNOTE: This diff has been truncated due to size. Generate the best PoC possible with the available information."

        prompt = f"""Analyze this security fix commit and generate a \
Proof-of-Concept (PoC) demonstration.

CVE: {cve_id}
Vulnerability: {cve_description}
Package: {package_info.get("name", "unknown")} \
({package_info.get("ecosystem", "unknown")})
Vulnerable Versions: {package_info.get("vulnerable_versions", "unknown")}

Fix Commit Diff:
{commit_diff}{context_note}

Extract the actual vulnerable and fixed code from the commit diff. \
Look for lines that were removed (-) as vulnerable code and lines that were added (+) as fixed code.

IMPORTANT: Return ONLY valid JSON, no additional text or explanations.
Use double quotes for all strings. Do NOT use backticks or template literals.
For multi-line code blocks, use \\n for newlines.
CRITICAL JSON ESCAPING RULES:
- ALL backslashes must be escaped as \\\\ (double backslash)
- Escape quotes as \\" (backslash quote)
- Escape newlines as \\n
- For any backslash in code (\\n, \\t, \\\\, \\"), write as \\\\n, \\\\t, \\\\\\\\, \\\\"
- For regex patterns, ALWAYS use raw string notation: "r'pattern'" instead of embedding escapes
- If a pattern contains backslashes, describe it in words rather than showing the literal pattern
- Example: Instead of "pattern.*?\\\\.test", write "pattern that matches .test files"
- All strings must be valid JSON - mentally validate each field

For vulnerable_function: Identify the SPECIFIC function/method in the {package_info.get("name", "unknown")} package
that was vulnerable, NOT the low-level library function it calls. Look for function definitions in the diff
(def function_name, class methods, etc.).

For risk_factors: Identify SPECIFIC conditions that make this vulnerability exploitable:
- Concurrency issues (race conditions, deadlocks)
- Input validation failures (missing checks, improper sanitization)
- Resource management (memory leaks, file handles, connections)
- Authentication/authorization bypasses
- State management issues

For attack_surface: Identify HOW an attacker can reach and trigger this vulnerability:
- Network accessible endpoints
- User input fields or parameters
- Configuration files or environment variables
- Concurrent operations or timing windows
- Specific application states or conditions

For function_signature: Extract the COMPLETE function signature including all parameters with their types and default values.
This provides context about the function's interface. Include the full function definition line from the code.

{{
  "vulnerable_function": "ClassName.method_name or function_name from the package being fixed",
  "function_signature": "def function_name(param1: type, param2: type = default) -> return_type:",
  "risk_factors": ["Race condition in locking mechanism", "Resource exhaustion during shutdown"],
  "attack_surface": ["Concurrent connection attempts", "Server shutdown timing"],
  "prerequisites": ["list", "of", "conditions", "needed", "for", "vulnerability"],
  "attack_vector": "brief description of how the attack works",
  "vulnerable_code": "EXACT code that was removed in the diff (lines starting with -), showing the vulnerable implementation",
  "fixed_code": "EXACT code that was added in the diff (lines starting with +), showing how the vulnerability was fixed",
  "test_case": "complete test case that demonstrates the vulnerability - show both the vulnerable behavior and how it's fixed",
  "reasoning": "explanation of the vulnerability and fix"
}}

Focus on:
1. Extract the ACTUAL vulnerable code from removed lines (-) in the diff - preserve original formatting
2. Extract the ACTUAL fixed code from added lines (+) in the diff - preserve original formatting
3. Show the real before/after comparison from the commit, not synthetic examples
4. Generate a test case that would fail with the vulnerable code but pass with the fixed code

Return valid JSON only - no markdown, no backticks, no explanations, just the JSON object."""

        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",  # Use Sonnet for better code generation
            max_tokens=1500,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}],
        )

        # Parse Claude's response
        try:
            import json
            import re

            content_block = response.content[0]
            if hasattr(content_block, "text"):
                claude_response = content_block.text.strip()
            else:
                raise ValueError("Unexpected response format from Claude API")

            # Log the raw response for debugging
            logging.debug(f"Raw Claude response: {claude_response[:200]}...")

            # Clean markdown formatting more aggressively
            if "```json" in claude_response:
                # Extract JSON between ```json and ```
                json_match = re.search(r"```json\s*(.*?)\s*```", claude_response, re.DOTALL)
                if json_match:
                    claude_response = json_match.group(1).strip()
            elif "```" in claude_response:
                # Remove any ``` markers
                claude_response = re.sub(r"```[a-zA-Z]*\s*", "", claude_response)
                claude_response = claude_response.replace("```", "").strip()

            # Fix common JSON syntax issues
            # Replace JavaScript template literals with double quotes
            claude_response = re.sub(r"`([^`]*)`", r'"\1"', claude_response)

            # Fix unescaped backslashes more aggressively
            # Replace all single backslashes with double backslashes, except those already properly escaped
            # This handles regex patterns and other problematic escapes
            def fix_backslashes(text: str) -> str:
                # First, protect already properly escaped sequences
                placeholders = {}

                # Protect already valid JSON escape sequences
                valid_escapes = ["\\n", "\\t", "\\r", "\\b", "\\f", '\\"', "\\\\", "\\/"]
                for placeholder_counter, escape in enumerate(valid_escapes):
                    placeholder = f"__ESCAPE_{placeholder_counter}__"
                    placeholders[placeholder] = escape
                    text = text.replace(escape, placeholder)

                # Now replace remaining single backslashes with double backslashes
                text = text.replace("\\", "\\\\")

                # Restore the protected sequences
                for placeholder, original in placeholders.items():
                    text = text.replace(placeholder, original)

                return text

            claude_response = fix_backslashes(claude_response)

            # Try to extract JSON from text that might have extra content
            json_match = re.search(r"\{.*\}", claude_response, re.DOTALL)
            if json_match:
                claude_response = json_match.group(0)

            logging.debug(f"Cleaned JSON: {claude_response[:200]}...")

            # Try to parse JSON with better error handling
            try:
                poc_result = json.loads(claude_response)
            except json.JSONDecodeError as e:
                # If JSON parsing fails, try to fix common issues
                logging.warning(f"Initial JSON parse failed: {e}")

                # Strategy 1: Try to fix unescaped quotes in code blocks
                fixed_response = re.sub(r'("vulnerable_code"\s*:\s*"[^"]*)"([^"]*)"([^"]*")', r'\1\\"\\2\\"\\3', claude_response)
                fixed_response = re.sub(r'("fixed_code"\s*:\s*"[^"]*)"([^"]*)"([^"]*")', r'\1\\"\\2\\"\\3', fixed_response)

                try:
                    poc_result = json.loads(fixed_response)
                    logging.info("JSON parsing succeeded after quote fixing")
                except json.JSONDecodeError as e2:
                    # Strategy 2: Try to fix backslash issues more carefully
                    logging.warning(f"Quote fixing failed: {e2}")

                    # Fix problematic code blocks by replacing them with placeholders
                    placeholder_response = claude_response

                    # Replace complex code blocks with simple placeholders
                    code_fields = ["vulnerable_code", "fixed_code", "test_case", "reasoning"]
                    for field in code_fields:
                        pattern = rf'("{field}"\s*:\s*)"([^"]*(?:\\.[^"]*)*)"'
                        placeholder_response = re.sub(pattern, rf'\1"[{field.upper()}_PLACEHOLDER]"', placeholder_response)

                    try:
                        poc_result = json.loads(placeholder_response)
                        logging.info("JSON parsing succeeded with placeholders")

                        # Try to extract the original content back using regex fallback
                        for field in code_fields:
                            original_match = re.search(rf'"{field}"\s*:\s*"([^"]*(?:\\.[^"]*)*)"', claude_response)
                            if original_match:
                                poc_result[field] = original_match.group(1)

                    except json.JSONDecodeError as e3:
                        # Final fallback: remove all regex patterns and complex code
                        logging.warning(f"All JSON parsing failed: {e3}. Using minimal extraction.")

                        # Create a minimal valid JSON by sanitizing all string values
                        sanitized_response = placeholder_response

                        # Replace any remaining problematic content in string values
                        for field in code_fields:
                            # Replace complex code blocks with simple descriptions
                            sanitized_response = re.sub(rf'("{field}"\s*:\s*)"[^"]*"', r'\1"[Code content removed due to parsing issues]"', sanitized_response)

                        try:
                            poc_result = json.loads(sanitized_response)
                            logging.info("JSON parsing succeeded with sanitized content")
                        except json.JSONDecodeError:
                            # If even sanitized JSON fails, raise the original error
                            raise e from None

            # Update with parsed results
            poc_data["risk_factors"] = poc_result.get("risk_factors", [])[:10]
            poc_data["attack_surface"] = poc_result.get("attack_surface", [])[:10]

            poc_data.update(
                {
                    "vulnerable_function": str(poc_result.get("vulnerable_function", ""))[:100],
                    "function_signature": str(poc_result.get("function_signature", ""))[:500],
                    "prerequisites": poc_result.get("prerequisites", [])[:10],  # Limit to 10 items
                    "attack_vector": str(poc_result.get("attack_vector", ""))[:300],
                    "vulnerable_code": str(poc_result.get("vulnerable_code", ""))[:2000],
                    "fixed_code": str(poc_result.get("fixed_code", ""))[:2000],
                    "test_case": str(poc_result.get("test_case", ""))[:3000],
                    "reasoning": str(poc_result.get("reasoning", ""))[:500],
                    "success": True,
                }
            )

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logging.warning(f"Failed to parse Claude PoC response: {e}")
            logging.warning(f"Raw response was: {claude_response[:500]}")
            poc_data["reasoning"] = f"PoC parse error: {str(e)[:100]}"

            # Try to extract some useful info even if JSON parsing fails
            if "vulnerable" in claude_response.lower():
                # Extract vulnerable_function if possible
                func_match = re.search(r'"vulnerable_function":\s*"([^"]+)"', claude_response)
                if func_match:
                    poc_data["vulnerable_function"] = func_match.group(1)

                # Extract function_signature if possible
                sig_match = re.search(r'"function_signature":\s*"([^"]+)"', claude_response)
                if sig_match:
                    poc_data["function_signature"] = sig_match.group(1)

                # Extract risk_factors if possible
                risk_match = re.search(r'"risk_factors":\s*\[([^\]]*)\]', claude_response)
                if risk_match:
                    risks_str = risk_match.group(1)
                    risks = [r.strip().strip('"') for r in risks_str.split(",") if r.strip()]
                    poc_data["risk_factors"] = risks

                # Extract attack_surface if possible
                surface_match = re.search(r'"attack_surface":\s*\[([^\]]*)\]', claude_response)
                if surface_match:
                    surface_str = surface_match.group(1)
                    surface = [s.strip().strip('"') for s in surface_str.split(",") if s.strip()]
                    poc_data["attack_surface"] = surface

                # Extract attack_vector if possible
                attack_match = re.search(r'"attack_vector":\s*"([^"]+)"', claude_response)
                if attack_match:
                    poc_data["attack_vector"] = attack_match.group(1)

                poc_data["success"] = True

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
    context: Dict[str, Any] = {
        "modified_files": [],
        "functions_changed": [],
        "function_signatures": [],
        "risk_factors": [],
        "attack_surface": [],
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

    # Extract complete function signatures
    signature_patterns = [
        r"def\s+\w+\s*\([^)]*\)[^:]*:",  # Python function signatures
        r"function\s+\w+\s*\([^)]*\)[^{]*{",  # JavaScript function signatures
        r"\w+\s*\([^)]*\)\s*{",  # Java/C-style function signatures
        r"fn\s+\w+\s*\([^)]*\)[^{]*{",  # Rust function signatures
    ]

    signatures = set()
    for pattern in signature_patterns:
        matches = re.findall(pattern, commit_diff)
        signatures.update(matches)

    context["function_signatures"] = list(signatures)[:10]  # Limit to 10

    # Extract basic risk factors from common patterns
    risk_indicators = [
        (r"for\s*\([^)]*\s+\w+\s*:\s*[^)]*\)", "Concurrent iteration over shared data"),
        (r"lock\(\)|unlock\(\)|synchronized", "Concurrency control present"),
        (r"close\(\)|shutdown\(\)|stop\(\)", "Resource cleanup operations"),
        (r"input|param|user|request", "User input processing"),
        (r"validate|sanitize|check", "Input validation present"),
        (r"memory|buffer|allocation", "Memory management"),
        (r"connection|socket|network", "Network operations"),
    ]

    risk_factors = []
    for pattern, description in risk_indicators:
        if re.search(pattern, commit_diff, re.IGNORECASE):
            risk_factors.append(description)

    context["risk_factors"] = risk_factors[:5]  # Limit to 5

    # Extract attack surface indicators
    attack_indicators = [
        (r"public|exposed|endpoint", "Publicly accessible"),
        (r"network|socket|connection", "Network accessible"),
        (r"concurrent|thread|parallel", "Concurrent operations"),
        (r"shutdown|stop|close", "State transition operations"),
        (r"input|param|argument", "User input channels"),
    ]

    attack_surface = []
    for pattern, description in attack_indicators:
        if re.search(pattern, commit_diff, re.IGNORECASE):
            attack_surface.append(description)

    context["attack_surface"] = attack_surface[:5]  # Limit to 5

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
