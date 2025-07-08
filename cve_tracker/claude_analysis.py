"""
Claude AI-powered commit content analysis using Anthropic's API.

Uses Claude in the cloud to analyze commit diffs against CVE descriptions.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import anthropic
from anthropic import APIError, RateLimitError


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
            results[commit["sha"]]["reasoning"] = (
                "No ANTHROPIC_API_KEY environment variable set"
            )
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

        prompt = f"""Analyze these {len(commits_data)} commits for relevance to the CVE.

CVE: {cve_id or "Unknown"}
Description: {cve_description}

COMMITS TO ANALYZE:
{commits_text}

For each commit, determine if it addresses the CVE. Return JSON:
{{
  "commit_1": {{"relevance_score": 0-15, "reasoning": "brief explanation",
                "vulnerability_type": "type", "confidence": "high/medium/low"}},
  "commit_2": {{"relevance_score": 0-15, "reasoning": "brief explanation",
                "vulnerability_type": "type", "confidence": "high/medium/low"}},
  ...
}}

Guidelines: 0=unrelated, 5=possibly related, 10=likely fix, 15=definitely fixes CVE"""

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
                claude_response = (
                    claude_response.replace("```json", "").replace("```", "").strip()
                )
            elif claude_response.startswith("```"):
                claude_response = claude_response.replace("```", "").strip()

            batch_analysis = json.loads(claude_response)

            # Map results back to commit SHAs
            for i, commit in enumerate(commits_data, 1):
                commit_key = f"commit_{i}"
                if commit_key in batch_analysis:
                    analysis = batch_analysis[commit_key]
                    results[commit["sha"]] = {
                        "relevance_score": min(
                            max(int(analysis.get("relevance_score", 0)), 0), 15
                        ),
                        "reasoning": str(
                            analysis.get("reasoning", "No reasoning provided")
                        )[:200],
                        "vulnerability_type": str(
                            analysis.get("vulnerability_type", "unknown")
                        )[:50],
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
                results[commit["sha"]]["reasoning"] = (
                    f"Batch parse error: {str(e)[:50]}"
                )

    except Exception as e:
        logging.error(f"Claude batch analysis error: {e}")
        for commit in commits_data:
            results[commit["sha"]]["reasoning"] = f"Batch analysis error: {str(e)[:50]}"

    return results


def analyze_commit_with_claude(
    commit_diff: str, cve_description: str, cve_id: Optional[str] = None
) -> Dict[str, Any]:
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
        prompt = f"""Analyze if this commit addresses the specified CVE.

CVE: {cve_id or "Unknown"}
Description: {cve_description}

Commit:
{commit_diff}

Consider:
1. Does the code fix the specific vulnerability mentioned?
2. Are changes in relevant files/functions for this security issue?
3. Do changes implement security improvements matching the CVE?

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
                claude_response = (
                    claude_response.replace("```json", "").replace("```", "").strip()
                )
            elif claude_response.startswith("```"):
                claude_response = claude_response.replace("```", "").strip()

            analysis_result = json.loads(claude_response)

            # Validate and sanitize the response
            analysis.update(
                {
                    "relevance_score": min(
                        max(int(analysis_result.get("relevance_score", 0)), 0), 15
                    ),
                    "reasoning": str(
                        analysis_result.get("reasoning", "No reasoning provided")
                    )[:200],
                    "vulnerability_type": str(
                        analysis_result.get("vulnerability_type", "unknown")
                    )[:50],
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
        analysis.update(
            {"reasoning": "Claude API rate limit exceeded", "confidence": "low"}
        )

    except APIError as e:
        logging.warning(f"Claude API error: {e}")
        analysis.update(
            {"reasoning": f"Claude API error: {str(e)[:100]}", "confidence": "low"}
        )

    except Exception as e:
        logging.error(f"Unexpected error in Claude analysis: {e}")
        analysis.update(
            {"reasoning": f"Analysis error: {str(e)[:100]}", "confidence": "low"}
        )

    return analysis
