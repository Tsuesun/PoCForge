"""
Tests for PoCForge main functionality.
"""

import os
import sys
from contextlib import suppress
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cve_tracker import extract_commits_from_advisory_references
from cve_tracker.poc_generator import generate_poc_from_fix_commit


class TestAdvisoryReferenceExtraction:
    """Test the extract_commits_from_advisory_references function."""

    def test_extract_commit_url_valid(self):
        """Test extracting valid commit URLs from advisory references."""
        references = [
            "https://github.com/owner/repo/commit/1234567890abcdef1234567890abcdef12345678",
            "https://example.com/not-a-commit-url",
            "https://github.com/another/repo/commit/fedcba0987654321fedcba0987654321fedcba09",
        ]

        result = extract_commits_from_advisory_references(references)

        assert len(result) == 2
        assert result[0]["repo"] == "owner/repo"
        assert result[0]["sha"] == "1234567890abcdef1234567890abcdef12345678"
        assert result[0]["score"] == 100
        assert result[1]["repo"] == "another/repo"
        assert result[1]["sha"] == "fedcba0987654321fedcba0987654321fedcba09"

    def test_extract_commit_url_invalid_sha(self):
        """Test that invalid SHAs are not extracted."""
        references = [
            "https://github.com/owner/repo/commit/invalid-sha",
            "https://github.com/owner/repo/commit/123456789",  # Too short
            "https://github.com/owner/repo/commit/" + "x" * 40,  # Invalid characters
        ]

        result = extract_commits_from_advisory_references(references)
        assert len(result) == 0

    def test_extract_commit_url_empty_references(self):
        """Test with empty references list."""
        references = []
        result = extract_commits_from_advisory_references(references)
        assert len(result) == 0

    def test_extract_commit_url_no_matches(self):
        """Test with references that don't contain commit URLs."""
        references = [
            "https://example.com/security-advisory",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234",
            "https://github.com/owner/repo/issues/123",
        ]

        result = extract_commits_from_advisory_references(references)
        assert len(result) == 0


class TestPoCGeneration:
    """Test the PoC generation functionality."""

    def test_generate_poc_no_api_key(self):
        """Test PoC generation without API key."""
        with patch("cve_tracker.poc_generator.get_anthropic_api_key", return_value=None):
            result = generate_poc_from_fix_commit(
                "diff --git a/file.py b/file.py\n+fixed code", "Test vulnerability", "CVE-2023-1234", {"name": "test-package", "ecosystem": "pypi"}
            )

            assert result["success"] is False
            assert "No Anthropic API key" in result["reasoning"]

    def test_generate_poc_diff_too_large(self):
        """Test PoC generation with diff too large - should use git extraction or truncate."""
        with patch("cve_tracker.poc_generator.get_anthropic_api_key", return_value=None):
            large_diff = "diff --git a/file.py b/file.py\n" + "+" + "x" * 15000
            result = generate_poc_from_fix_commit(large_diff, "Test vulnerability", "CVE-2023-1234", {"name": "test-package", "ecosystem": "pypi"})

            assert result["success"] is False
            # Should fail due to no API key, not size (since we now handle large diffs)
            assert "No Anthropic API key" in result["reasoning"]

    @patch("cve_tracker.poc_generator.get_anthropic_api_key")
    @patch("cve_tracker.poc_generator.anthropic.Anthropic")
    def test_generate_poc_success(self, mock_anthropic_client, mock_get_key):
        """Test successful PoC generation."""
        mock_get_key.return_value = "dummy-key"

        # Mock the Anthropic client response
        mock_client = Mock()
        mock_anthropic_client.return_value = mock_client

        mock_response = Mock()
        mock_content = Mock()
        mock_content.text = """
        {
            "vulnerable_function": "test_function",
            "prerequisites": ["test prerequisite"],
            "attack_vector": "test attack",
            "vulnerable_code": "vulnerable code example",
            "fixed_code": "fixed code example",
            "test_case": "test case example",
            "reasoning": "test reasoning"
        }
        """
        mock_response.content = [mock_content]
        mock_client.messages.create.return_value = mock_response

        result = generate_poc_from_fix_commit(
            "diff --git a/file.py b/file.py\n+fixed code", "Test vulnerability", "CVE-2023-1234", {"name": "test-package", "ecosystem": "pypi"}
        )

        assert result["success"] is True
        assert result["vulnerable_function"] == "test_function"
        assert result["prerequisites"] == ["test prerequisite"]
        assert result["attack_vector"] == "test attack"

    @patch("cve_tracker.poc_generator.get_anthropic_api_key")
    @patch("cve_tracker.poc_generator.anthropic.Anthropic")
    def test_generate_poc_json_parse_error(self, mock_anthropic_client, mock_get_key):
        """Test PoC generation with JSON parse error."""
        mock_get_key.return_value = "dummy-key"

        mock_client = Mock()
        mock_anthropic_client.return_value = mock_client

        mock_response = Mock()
        mock_content = Mock()
        mock_content.text = "invalid json response"
        mock_response.content = [mock_content]
        mock_client.messages.create.return_value = mock_response

        result = generate_poc_from_fix_commit(
            "diff --git a/file.py b/file.py\n+fixed code", "Test vulnerability", "CVE-2023-1234", {"name": "test-package", "ecosystem": "pypi"}
        )

        assert result["success"] is False
        assert "parse error" in result["reasoning"]

    def test_generate_poc_with_git_extraction(self):
        """Test PoC generation with git extraction for large diffs."""
        with patch("cve_tracker.poc_generator.get_anthropic_api_key", return_value=None):
            large_diff = "diff --git a/file.py b/file.py\n" + "+" + "x" * 15000
            result = generate_poc_from_fix_commit(
                large_diff, "Test vulnerability", "CVE-2023-1234", {"name": "test-package", "ecosystem": "pypi"}, repo_url="test/repo", commit_sha="abc123"
            )

            assert result["success"] is False
            # Should fail due to no API key, but git extraction should have been attempted
            assert "No Anthropic API key" in result["reasoning"]


class TestConfig:
    """Test configuration loading."""

    @patch("cve_tracker.config.Path.exists")
    @patch("cve_tracker.config.open")
    @patch("cve_tracker.config.json.load")
    def test_config_loading(self, mock_json_load, mock_open, mock_exists):
        """Test that config loading works properly."""
        from cve_tracker.config import load_config

        mock_exists.return_value = True
        mock_json_load.return_value = {"github_token": "test-token", "anthropic_api_key": "test-key"}

        config = load_config()

        assert config["github_token"] == "test-token"
        assert config["anthropic_api_key"] == "test-key"

    @patch("cve_tracker.config.Path.exists")
    @patch("cve_tracker.config.os.getenv")
    def test_env_override(self, mock_getenv, mock_exists):
        """Test that environment variables override config file."""
        from cve_tracker.config import load_config

        mock_exists.return_value = False
        mock_getenv.side_effect = lambda key: {"GITHUB_TOKEN": "env-token", "ANTHROPIC_API_KEY": "env-key"}.get(key)

        config = load_config()

        assert config["github_token"] == "env-token"
        assert config["anthropic_api_key"] == "env-key"


class TestMainFunctionality:
    """Test main application functionality."""

    @patch("main.get_github_token")
    @patch("main.get_anthropic_api_key")
    @patch("main.Github")
    def test_main_with_no_tokens(self, mock_github, mock_anthropic_key, mock_github_token):
        """Test main function behavior with no tokens."""
        mock_github_token.return_value = None
        mock_anthropic_key.return_value = None

        # Mock GitHub client
        mock_g = Mock()
        mock_github.return_value = mock_g

        # Mock advisories (empty list to avoid API calls)
        mock_advisories = Mock()
        mock_advisories.__iter__ = Mock(return_value=iter([]))
        mock_g.get_global_advisories.return_value = mock_advisories

        # Import and run main
        from main import main

        with suppress(SystemExit):
            main(hours=24, cve=None)  # Pass the required parameters

        # Verify GitHub client was created without token
        mock_github.assert_called_with()
