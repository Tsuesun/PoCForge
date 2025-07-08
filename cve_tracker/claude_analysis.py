"""
Claude AI-powered commit content analysis using Anthropic's API.

Uses Claude in the cloud to analyze commit diffs against CVE descriptions.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import anthropic
from anthropic import APIError, RateLimitError


def screen_commits_with_claude(
    commits_data: List[Dict[str, str]],
    cve_description: str,
    cve_id: Optional[str] = None,
) -> Dict[str, int]:
    """
    Quick AI screening to identify potentially security-relevant commits.

    This is the first stage filter - much faster than detailed analysis.
    Only commits scored >0 will proceed to detailed analysis.

    Args:
        commits_data: List of dicts with 'sha', 'message' keys (no diff needed)
        cve_description: Description of the CVE vulnerability
        cve_id: Optional CVE ID for additional context

    Returns:
        Dictionary mapping commit SHA to screening score (0-10)
    """
    results = {}
    for commit in commits_data:
        results[commit["sha"]] = 0

    # Check for API key
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        # Fallback to keyword-based screening if no Claude
        return _fallback_keyword_screening(commits_data)

    # Skip if too many commits
    if len(commits_data) > 25:  # Higher limit for screening
        return _fallback_keyword_screening(commits_data)

    try:
        client = anthropic.Anthropic(api_key=api_key)

        # Build commit summaries for screening (just message, no diff)
        commit_summaries = []
        for i, commit in enumerate(commits_data, 1):
            summary = f"COMMIT {i}: {commit['sha'][:8]} - {commit['message'][:150]}"
            commit_summaries.append(summary)

        commits_text = "\n".join(commit_summaries)

        prompt = f"""Screen these {len(commits_data)} commits to find ones that \
might fix this specific vulnerability.

CVE: {cve_id or "Unknown"}
Vulnerability: {cve_description}

COMMITS TO SCREEN:
{commits_text}

For each commit, score (0-10) based on how well the commit message \
matches the specific vulnerability described above:
- 0: Unrelated to this vulnerability (different security issue, docs, tests, etc.)
- 3: Generic security fix that might be related
- 7: Commit mentions similar concepts (e.g., regex, validation, parsing)
- 10: Commit directly addresses this vulnerability type or mentions the CVE

Return JSON: {{"commit_1": 5, "commit_2": 0, "commit_3": 8, ...}}

Focus on matching the SPECIFIC vulnerability described, not just \
general security relevance."""

        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=400,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}],
        )

        # Parse response
        try:
            import json

            content_block = response.content[0]
            if hasattr(content_block, "text"):
                claude_response = content_block.text.strip()  # type: ignore
            else:
                raise ValueError("Unexpected response format from Claude API")

            # Clean markdown formatting
            if claude_response.startswith("```json"):
                claude_response = claude_response.replace("```json", "").replace("```", "").strip()
            elif claude_response.startswith("```"):
                claude_response = claude_response.replace("```", "").strip()

            screening_results = json.loads(claude_response)

            # Map results back to commit SHAs
            for i, commit in enumerate(commits_data, 1):
                commit_key = f"commit_{i}"
                if commit_key in screening_results:
                    score = screening_results[commit_key]
                    results[commit["sha"]] = min(max(int(score), 0), 10)

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logging.warning(f"Failed to parse Claude screening response: {e}")
            return _fallback_keyword_screening(commits_data)

    except Exception as e:
        logging.warning(f"Claude screening error: {e}")
        return _fallback_keyword_screening(commits_data)

    return results


def _fallback_keyword_screening(commits_data: List[Dict[str, str]]) -> Dict[str, int]:
    """Fallback to keyword-based screening when Claude is unavailable."""
    from .security_scoring import SECURITY_KEYWORDS

    results = {}
    for commit in commits_data:
        message_lower = commit["message"].lower()
        score = 0

        # Check for security keywords
        for keyword in SECURITY_KEYWORDS:
            if keyword.lower() in message_lower:
                score += 2

        # High-value patterns
        if any(pattern in message_lower for pattern in ["cve-", "security", "vulnerability"]):
            score += 5

        if message_lower.startswith(("fix", "security", "patch")):
            score += 3

        results[commit["sha"]] = min(score, 10)

    return results


def analyze_commits_batch_with_claude(
    commits_data: List[Dict[str, str]],
    cve_description: str,
    cve_id: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Analyze multiple commits in a single Claude API call for efficiency.

    Args:
        commits_data: List of dicts with 'sha', 'message', 'diff' keys
        cve_description: Description of the CVE vulnerability
        cve_id: Optional CVE ID for additional context

    Returns:
        Dictionary mapping commit SHA to analysis results
    """
    # Initialize default response
    results = {}
    for commit in commits_data:
        results[commit["sha"]] = {
            "relevance_score": 0,
            "reasoning": "No Claude API key available",
            "vulnerability_type": "unknown",
            "confidence": "low",
        }

    # Check for API key
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        for commit in commits_data:
            results[commit["sha"]]["reasoning"] = "No ANTHROPIC_API_KEY environment variable set"
        return results

    # Skip if too many commits or total size too large
    if len(commits_data) > 10:
        for commit in commits_data:
            results[commit["sha"]]["reasoning"] = "Too many commits for batch analysis"
        return results

    total_size = sum(len(commit.get("diff", "")) for commit in commits_data)
    if total_size > 15000:  # 15KB limit for batch
        for commit in commits_data:
            results[commit["sha"]]["reasoning"] = "Batch too large for Claude API"
        return results

    try:
        client = anthropic.Anthropic(api_key=api_key)

        # Build commit summaries for the prompt
        commit_summaries = []
        for i, commit in enumerate(commits_data, 1):
            summary = f"""COMMIT {i}:
SHA: {commit["sha"][:8]}
Message: {commit["message"][:100]}
Changes:
{commit.get("diff", "No diff available")[:1000]}
---"""
            commit_summaries.append(summary)

        commits_text = "\n\n".join(commit_summaries)

        prompt = f"""Analyze these {len(commits_data)} commits to see if they \
fix the SPECIFIC vulnerability described below.

CVE: {cve_id or "Unknown"}
Vulnerability: {cve_description}

COMMITS TO ANALYZE:
{commits_text}

For each commit, determine if it fixes the EXACT vulnerability \
described above. Be strict - only high scores for commits that actually \
address THIS specific vulnerability type.

Return JSON:
{{
  "commit_1": {{"relevance_score": 0-15, "reasoning": "brief explanation",
                "vulnerability_type": "type", "confidence": "high/medium/low"}},
  "commit_2": {{"relevance_score": 0-15, "reasoning": "brief explanation",
                "vulnerability_type": "type", "confidence": "high/medium/low"}},
  ...
}}

Guidelines: 0=unrelated to this vulnerability, 5=possibly related, \
10=likely fixes this vulnerability, 15=definitely fixes this specific CVE"""

        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=800,  # Increase for multiple commits
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}],
        )

        # Parse Claude's response
        try:
            import json

            # Get text content from the response
            content_block = response.content[0]
            if hasattr(content_block, "text"):
                claude_response = content_block.text.strip()  # type: ignore
            else:
                raise ValueError("Unexpected response format from Claude API")

            # Remove markdown formatting if present
            if claude_response.startswith("```json"):
                claude_response = claude_response.replace("```json", "").replace("```", "").strip()
            elif claude_response.startswith("```"):
                claude_response = claude_response.replace("```", "").strip()

            batch_analysis = json.loads(claude_response)

            # Map results back to commit SHAs
            for i, commit in enumerate(commits_data, 1):
                commit_key = f"commit_{i}"
                if commit_key in batch_analysis:
                    analysis = batch_analysis[commit_key]
                    results[commit["sha"]] = {
                        "relevance_score": min(max(int(analysis.get("relevance_score", 0)), 0), 15),
                        "reasoning": str(analysis.get("reasoning", "No reasoning provided"))[:200],
                        "vulnerability_type": str(analysis.get("vulnerability_type", "unknown"))[:50],
                        "confidence": str(analysis.get("confidence", "low")).lower(),
                    }

                    # Validate confidence
                    if results[commit["sha"]]["confidence"] not in [
                        "high",
                        "medium",
                        "low",
                    ]:
                        results[commit["sha"]]["confidence"] = "low"

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logging.warning(f"Failed to parse Claude batch response: {e}")
            for commit in commits_data:
                results[commit["sha"]]["reasoning"] = f"Batch parse error: {str(e)[:50]}"

    except Exception as e:
        logging.error(f"Claude batch analysis error: {e}")
        for commit in commits_data:
            results[commit["sha"]]["reasoning"] = f"Batch analysis error: {str(e)[:50]}"

    return results


def analyze_commit_with_claude(commit_diff: str, cve_description: str, cve_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Use Claude's API to analyze a commit diff against a CVE description.

    Args:
        commit_diff: The git diff/patch content of the commit
        cve_description: Description of the CVE vulnerability
        cve_id: Optional CVE ID for additional context

    Returns:
        Dictionary with relevance_score, reasoning, and vulnerability_type
    """
    # Initialize default response
    analysis = {
        "relevance_score": 0,
        "reasoning": "No Claude API key available",
        "vulnerability_type": "unknown",
        "confidence": "low",
    }

    # Check for API key
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        analysis["reasoning"] = "No ANTHROPIC_API_KEY environment variable set"
        return analysis

    # Skip analysis if diff is too large (>8KB) to avoid token limits
    if len(commit_diff) > 8000:
        analysis.update(
            {
                "reasoning": "Commit diff too large for Claude API analysis",
                "confidence": "low",
            }
        )
        return analysis

    try:
        client = anthropic.Anthropic(api_key=api_key)

        # Create the analysis prompt
        prompt = f"""Analyze if this commit fixes the SPECIFIC vulnerability \
described below.

CVE: {cve_id or "Unknown"}
Vulnerability: {cve_description}

Commit:
{commit_diff}

Does this commit fix the EXACT vulnerability described above? Consider:
1. Does the code change address the specific vulnerability type mentioned?
2. Are the file changes relevant to fixing this particular security issue?
3. Do the code changes match what would be needed to fix this vulnerability?

Be strict - only high scores for commits that actually fix THIS vulnerability.

Return JSON only:
{{
  "relevance_score": 0-15,
  "reasoning": "brief explanation (max 100 words)",
  "vulnerability_type": "ReDoS/XSS/PathTraversal/etc",
  "confidence": "high/medium/low"
}}"""

        response = client.messages.create(
            model="claude-3-haiku-20240307",  # Fast and cost-effective
            max_tokens=300,
            temperature=0.1,  # Low temperature for consistent analysis
            messages=[{"role": "user", "content": prompt}],
        )

        # Parse Claude's response
        try:
            import json

            # Get text content from the response
            content_block = response.content[0]
            if hasattr(content_block, "text"):
                claude_response = content_block.text.strip()  # type: ignore
            else:
                raise ValueError("Unexpected response format from Claude API")

            # Remove any markdown formatting if present
            if claude_response.startswith("```json"):
                claude_response = claude_response.replace("```json", "").replace("```", "").strip()
            elif claude_response.startswith("```"):
                claude_response = claude_response.replace("```", "").strip()

            analysis_result = json.loads(claude_response)

            # Validate and sanitize the response
            analysis.update(
                {
                    "relevance_score": min(max(int(analysis_result.get("relevance_score", 0)), 0), 15),
                    "reasoning": str(analysis_result.get("reasoning", "No reasoning provided"))[:200],
                    "vulnerability_type": str(analysis_result.get("vulnerability_type", "unknown"))[:50],
                    "confidence": str(analysis_result.get("confidence", "low")).lower(),
                }
            )

            # Ensure confidence is valid
            if analysis["confidence"] not in ["high", "medium", "low"]:
                analysis["confidence"] = "low"

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logging.warning(f"Failed to parse Claude response: {e}")
            logging.debug(f"Raw Claude response: {repr(claude_response[:500])}")

            # Try to extract at least the score if JSON is malformed
            try:
                import re

                score_match = re.search(r'"relevance_score":\s*(\d+)', claude_response)
                if score_match:
                    extracted_score = min(max(int(score_match.group(1)), 0), 15)
                    analysis.update(
                        {
                            "relevance_score": extracted_score,
                            "reasoning": "Extracted from malformed Claude response",
                            "confidence": "low",
                        }
                    )
                    return analysis
            except Exception:
                pass

            analysis.update(
                {
                    "relevance_score": 0,
                    "reasoning": f"JSON parse error: {str(e)[:50]}",
                    "confidence": "low",
                }
            )

    except RateLimitError:
        logging.warning("Claude API rate limit exceeded")
        analysis.update({"reasoning": "Claude API rate limit exceeded", "confidence": "low"})

    except APIError as e:
        logging.warning(f"Claude API error: {e}")
        analysis.update({"reasoning": f"Claude API error: {str(e)[:100]}", "confidence": "low"})

    except Exception as e:
        logging.error(f"Unexpected error in Claude analysis: {e}")
        analysis.update({"reasoning": f"Analysis error: {str(e)[:100]}", "confidence": "low"})

    return analysis
