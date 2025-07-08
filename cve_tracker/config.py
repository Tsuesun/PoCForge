"""
Configuration management for CVE-to-PoC Generator.

Loads API keys from config.json file or environment variables.
"""

import json
import os
from pathlib import Path
from typing import Optional


def load_config() -> dict:
    """
    Load configuration from config.json file or environment variables.

    Priority:
    1. Environment variables (highest priority)
    2. config.json file
    3. Default empty values

    Returns:
        Dictionary with configuration values
    """
    config = {"github_token": "", "anthropic_api_key": ""}

    # Try to load from config.json
    config_file = Path(__file__).parent.parent / "config.json"
    if config_file.exists():
        try:
            with open(config_file, "r") as f:
                file_config = json.load(f)
                config.update(file_config)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load config.json: {e}")

    # Environment variables override file config
    if os.getenv("GITHUB_TOKEN"):
        config["github_token"] = os.getenv("GITHUB_TOKEN")

    if os.getenv("ANTHROPIC_API_KEY"):
        config["anthropic_api_key"] = os.getenv("ANTHROPIC_API_KEY")

    return config


def get_github_token() -> Optional[str]:
    """Get GitHub token from config."""
    config = load_config()
    token = config.get("github_token", "").strip()
    return token if token else None


def get_anthropic_api_key() -> Optional[str]:
    """Get Anthropic API key from config."""
    config = load_config()
    key = config.get("anthropic_api_key", "").strip()
    return key if key else None
