"""
Tests for the CVE to Fix Tracker main functionality.
"""

import os

# Import functions from main module
import sys
from datetime import datetime, timezone
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cve_tracker import (
    calculate_commit_security_relevance_score,
    calculate_security_relevance_score,
    find_repository,
    get_potential_repos,
    search_security_commits,
    search_security_prs,
)


class TestGetPotentialRepos:
    """Test the get_potential_repos function."""

    def test_npm_package_without_org(self):
        """Test npm package without organization."""
        result = get_potential_repos("express", "npm")
        assert "express" in result
        assert len(result) <= 3

    def test_npm_package_with_org(self):
        """Test npm package with organization."""
        result = get_potential_repos("@typescript-eslint/parser", "npm")
        assert "@typescript-eslint/parser" in result
        # The current implementation doesn't strip the @ for org packages
        # It just adds the same package name twice

    def test_pypi_package(self):
        """Test PyPI package with various naming conventions."""
        result = get_potential_repos("my-package", "pypi")
        assert "my-package" in result
        assert "my_package" in result

        result2 = get_potential_repos("my_package", "pypi")
        assert "my_package" in result2
        assert "my-package" in result2

    def test_maven_package(self):
        """Test Maven package with group:artifact pattern."""
        result = get_potential_repos("org.springframework:spring-core", "maven")
        assert "spring-core" in result

    def test_gradle_package(self):
        """Test Gradle package with group:artifact pattern."""
        result = get_potential_repos(
            "com.fasterxml.jackson.core:jackson-core", "gradle"
        )
        assert "jackson-core" in result

    def test_nuget_package(self):
        """Test NuGet package."""
        result = get_potential_repos("Newtonsoft.Json", "nuget")
        assert "Newtonsoft.Json" in result

    def test_unknown_ecosystem(self):
        """Test unknown package ecosystem."""
        result = get_potential_repos("some-package", "unknown")
        assert "some-package" in result

    def test_result_limit(self):
        """Test that results are limited to 3 items."""
        result = get_potential_repos("test-package", "pypi")
        assert len(result) <= 3


class TestSecurityRelevanceScoring:
    """Test security relevance scoring functions."""

    def create_mock_pr(self, title: str, body: str = "") -> Mock:
        """Create a mock pull request."""
        pr = Mock()
        pr.title = title
        pr.body = body
        return pr

    def create_mock_commit(self, message: str) -> Mock:
        """Create a mock commit."""
        commit = Mock()
        commit.commit.message = message
        return commit

    def test_pr_cve_direct_match(self):
        """Test PR scoring with direct CVE match."""
        pr = self.create_mock_pr("Fix CVE-2023-1234 vulnerability", "Security fix")
        score = calculate_security_relevance_score(
            pr, ["security", "fix"], "CVE-2023-1234"
        )
        assert score >= 10  # Should get CVE match bonus

    def test_pr_security_keywords(self):
        """Test PR scoring with security keywords."""
        pr = self.create_mock_pr("Fix security vulnerability in auth", "XSS prevention")
        score = calculate_security_relevance_score(
            pr, ["security", "vulnerability", "XSS"], None
        )
        assert score > 0
        # Should get points for security, vulnerability, XSS, and fix + security combo

    def test_pr_fix_prefix(self):
        """Test PR scoring with fix prefix."""
        pr = self.create_mock_pr("fix: buffer overflow in parser", "")
        score = calculate_security_relevance_score(pr, ["fix", "buffer overflow"], None)
        assert score > 0

    def test_pr_no_security_content(self):
        """Test PR with no security-related content."""
        pr = self.create_mock_pr("Add new feature", "Implements user dashboard")
        score = calculate_security_relevance_score(
            pr, ["security", "vulnerability"], None
        )
        assert score == 0

    def test_commit_cve_direct_match(self):
        """Test commit scoring with direct CVE match."""
        commit = self.create_mock_commit("fix: CVE-2023-1234 buffer overflow")
        score = calculate_commit_security_relevance_score(
            commit, ["security", "fix"], "CVE-2023-1234"
        )
        assert score >= 10

    def test_commit_redos_detection(self):
        """Test commit scoring for ReDoS vulnerabilities."""
        commit = self.create_mock_commit("fix: redos vulnerability in regex pattern")
        score = calculate_commit_security_relevance_score(
            commit, ["redos", "regex", "fix"], None
        )
        assert score > 0

    def test_commit_security_prefix(self):
        """Test commit scoring with security prefix."""
        commit = self.create_mock_commit("security: patch XSS vulnerability")
        score = calculate_commit_security_relevance_score(
            commit, ["security", "XSS"], None
        )
        assert score > 0

    def test_commit_no_security_content(self):
        """Test commit with no security content."""
        commit = self.create_mock_commit("docs: update README")
        score = calculate_commit_security_relevance_score(
            commit, ["security", "vulnerability"], None
        )
        assert score == 0


class TestRepositoryDiscovery:
    """Test repository discovery functionality."""

    @patch("cve_tracker.github_search.Github")
    def test_find_repository_direct_path(self, mock_github_class):
        """Test finding repository with direct owner/repo path."""
        mock_github = Mock()
        mock_github_class.return_value = mock_github

        mock_repo = Mock()
        mock_repo.full_name = "owner/repo"
        mock_github.get_repo.return_value = mock_repo

        result = find_repository(mock_github, "owner/repo")
        assert result == mock_repo
        mock_github.get_repo.assert_called_once_with("owner/repo")

    @patch("cve_tracker.github_search.Github")
    def test_find_repository_search_exact_match(self, mock_github_class):
        """Test finding repository through search with exact name match."""
        mock_github = Mock()
        mock_github_class.return_value = mock_github

        mock_repo1 = Mock()
        mock_repo1.name = "express"
        mock_repo2 = Mock()
        mock_repo2.name = "express-server"

        mock_search_result = Mock()
        mock_search_result.totalCount = 2
        mock_search_result.__iter__ = Mock(return_value=iter([mock_repo1, mock_repo2]))
        mock_github.search_repositories.return_value = mock_search_result

        result = find_repository(mock_github, "express")
        assert result == mock_repo1  # Should return exact match

    @patch("cve_tracker.github_search.Github")
    def test_find_repository_search_first_result(self, mock_github_class):
        """Test finding repository through search, returning first result."""
        mock_github = Mock()
        mock_github_class.return_value = mock_github

        mock_repo = Mock()
        mock_repo.name = "similar-package"

        mock_search_result = Mock()
        mock_search_result.totalCount = 1
        mock_search_result.__iter__ = Mock(return_value=iter([mock_repo]))
        mock_search_result.__getitem__ = Mock(return_value=mock_repo)
        mock_github.search_repositories.return_value = mock_search_result

        result = find_repository(mock_github, "package")
        assert result == mock_repo

    @patch("cve_tracker.github_search.Github")
    def test_find_repository_not_found(self, mock_github_class):
        """Test repository not found scenario."""
        mock_github = Mock()
        mock_github_class.return_value = mock_github

        mock_search_result = Mock()
        mock_search_result.totalCount = 0
        mock_github.search_repositories.return_value = mock_search_result

        result = find_repository(mock_github, "nonexistent-package")
        assert result is None

    @patch("cve_tracker.github_search.Github")
    def test_find_repository_exception_handling(self, mock_github_class):
        """Test repository search with exception handling."""
        mock_github = Mock()
        mock_github_class.return_value = mock_github
        mock_github.get_repo.side_effect = Exception("API error")

        result = find_repository(mock_github, "owner/repo")
        assert result is None


class TestSearchFunctions:
    """Test the search functions for PRs and commits."""

    def create_mock_repo(self, name: str) -> Mock:
        """Create a mock repository."""
        repo = Mock()
        repo.full_name = name
        return repo

    def create_mock_pr(self, number: int, title: str, state: str = "closed") -> Mock:
        """Create a mock pull request."""
        pr = Mock()
        pr.number = number
        pr.title = title
        pr.state = state
        pr.body = ""
        pr.html_url = f"https://github.com/test/repo/pull/{number}"
        pr.merged = True if state == "closed" else None
        return pr

    def create_mock_commit(
        self, sha: str, message: str, date: str = "2023-01-01"
    ) -> Mock:
        """Create a mock commit."""
        commit = Mock()
        commit.sha = sha
        commit.html_url = f"https://github.com/test/repo/commit/{sha}"
        commit.commit.message = message
        commit.commit.author.date = datetime.fromisoformat(date).replace(
            tzinfo=timezone.utc
        )
        return commit

    @patch("cve_tracker.github_search.find_repository")
    def test_search_security_prs_success(self, mock_find_repo):
        """Test successful PR search."""
        mock_repo = self.create_mock_repo("test/repo")
        mock_find_repo.return_value = mock_repo

        # Mock PRs
        pr1 = self.create_mock_pr(1, "fix: security vulnerability")
        pr2 = self.create_mock_pr(2, "feat: add new feature")
        pr3 = self.create_mock_pr(3, "security: patch XSS issue")

        mock_repo.get_pulls.return_value = [pr1, pr2, pr3][:10]  # Simulate slicing

        mock_github = Mock()
        result = search_security_prs(
            mock_github, ["test-repo"], "CVE-2023-1234", "test-package"
        )

        # Should find security-related PRs
        assert len(result) >= 1
        assert any("security" in pr["title"].lower() for pr in result)

    @patch("cve_tracker.github_search.find_repository")
    def test_search_security_commits_success(self, mock_find_repo):
        """Test successful commit search."""
        mock_repo = self.create_mock_repo("test/repo")
        mock_find_repo.return_value = mock_repo

        # Mock commits
        commit1 = self.create_mock_commit(
            "abc123", "fix: security vulnerability in auth"
        )
        commit2 = self.create_mock_commit("def456", "docs: update README")
        commit3 = self.create_mock_commit("ghi789", "patch: XSS prevention")

        mock_repo.get_commits.return_value = [commit1, commit2, commit3][
            :50
        ]  # Simulate slicing

        mock_github = Mock()
        result = search_security_commits(
            mock_github, ["test-repo"], "CVE-2023-1234", "test-package"
        )

        # Should find security-related commits
        assert len(result) >= 1
        assert any("security" in commit["message"].lower() for commit in result)

    @patch("cve_tracker.github_search.find_repository")
    def test_search_no_repository_found(self, mock_find_repo):
        """Test search when repository is not found."""
        mock_find_repo.return_value = None

        mock_github = Mock()
        result_prs = search_security_prs(mock_github, ["nonexistent"], None, "package")
        result_commits = search_security_commits(
            mock_github, ["nonexistent"], None, "package"
        )

        assert result_prs == []
        assert result_commits == []

    @patch("cve_tracker.github_search.find_repository")
    def test_search_with_exception(self, mock_find_repo):
        """Test search with repository API exception."""
        mock_repo = self.create_mock_repo("test/repo")
        mock_repo.get_pulls.side_effect = Exception("API rate limit")
        mock_repo.get_commits.side_effect = Exception("API rate limit")
        mock_find_repo.return_value = mock_repo

        mock_github = Mock()
        result_prs = search_security_prs(mock_github, ["test-repo"], None, "package")
        result_commits = search_security_commits(
            mock_github, ["test-repo"], None, "package"
        )

        # Should handle exceptions gracefully
        assert result_prs == []
        assert result_commits == []


class TestIntegration:
    """Integration tests for combined functionality."""

    def test_security_keyword_coverage(self):
        """Test that our security keywords cover major vulnerability types."""
        # This test ensures we're detecting common security issues
        test_cases = [
            ("fix: XSS vulnerability", True),
            ("patch: SQL injection", True),
            ("security: CSRF protection", True),
            ("fix: buffer overflow", True),
            ("patch: redos in regex", True),
            ("update: dependency version", False),
            ("feat: new UI component", False),
        ]

        security_keywords = [
            "security",
            "vulnerability",
            "CVE",
            "fix",
            "patch",
            "exploit",
            "XSS",
            "SQL injection",
            "CSRF",
            "authentication",
            "authorization",
            "sanitize",
            "validate",
            "escape",
            "buffer overflow",
            "DoS",
            "redos",
            "privilege escalation",
            "code injection",
            "path traversal",
            "regex",
        ]

        for message, should_detect in test_cases:
            mock_commit = Mock()
            mock_commit.commit.message = message

            score = calculate_commit_security_relevance_score(
                mock_commit, security_keywords, None
            )

            if should_detect:
                assert score > 0, f"Should detect security content in: {message}"
            else:
                assert score == 0, f"Should not detect security content in: {message}"

    def test_ecosystem_coverage(self):
        """Test that we handle all major package ecosystems."""
        test_cases = [
            ("npm", "test-package", True),
            ("pypi", "test-package", True),
            (
                "maven",
                "org.example:test-package",
                True,
            ),  # Maven needs group:artifact format
            (
                "gradle",
                "org.example:test-package",
                True,
            ),  # Gradle needs group:artifact format
            ("nuget", "test-package", True),
            ("unknown", "test-package", True),
            ("maven", "test-package", False),  # Maven without : returns empty
        ]

        for ecosystem, package, should_have_results in test_cases:
            result = get_potential_repos(package, ecosystem)
            if should_have_results:
                assert len(result) > 0, (
                    f"Should return repos for ecosystem: {ecosystem} "
                    f"with package: {package}"
                )
            assert len(result) <= 3, f"Should limit results for ecosystem: {ecosystem}"
