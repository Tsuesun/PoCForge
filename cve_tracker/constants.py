"""Constants for PoCForge configuration and limits."""

# Default values
DEFAULT_HOURS_LOOKBACK = 24
DEFAULT_JSON_INDENT = 2

# Limits and thresholds
MAX_DIFF_SIZE = 12000  # Size in characters before using git extraction
DIFF_TRUNCATION_SIZE = 10000  # Size to truncate diffs when too large
GIT_LARGE_DIFF_THRESHOLD = 15000  # Size threshold for git extraction switching
GIT_CLONE_DEPTH = 10  # Depth for shallow git clones
GIT_CONTEXT_LINES = 3  # Lines of context for git diff

# Display limits
MAX_DISPLAY_RESULTS = 5  # Maximum number of CVE results to show
MAX_FILES_TO_PROCESS = 5  # Maximum number of files to process from commit
MAX_DISPLAY_ITEMS = 3  # Maximum items to show in lists (risk factors, etc.)
SEPARATOR_LINE_LENGTH = 80  # Length of separator lines

# Output field length limits
MAX_VULNERABLE_FUNCTION_LENGTH = 100
MAX_FUNCTION_SIGNATURE_LENGTH = 500
MAX_ATTACK_VECTOR_LENGTH = 300
MAX_VULNERABLE_CODE_LENGTH = 2000
MAX_FIXED_CODE_LENGTH = 2000
MAX_TEST_CASE_LENGTH = 3000
MAX_REASONING_LENGTH = 500
MAX_ERROR_MESSAGE_LENGTH = 100
MAX_ERROR_REASON_LENGTH = 50
MAX_RAW_RESPONSE_LENGTH = 500
MAX_DEBUG_RESPONSE_LENGTH = 200

# API limits
CLAUDE_MAX_TOKENS = 1500
CLAUDE_TEMPERATURE = 0.1
CLAUDE_MODEL = "claude-3-5-sonnet-20241022"

# Collection limits
MAX_RISK_FACTORS = 10
MAX_ATTACK_SURFACE = 10
MAX_PREREQUISITES = 10
MAX_FUNCTIONS_CHANGED = 10
MAX_FUNCTION_SIGNATURES = 10

# GitHub commit pattern
GITHUB_COMMIT_SHA_LENGTH = 40
GITHUB_COMMIT_SCORE = 100  # Score for direct advisory commits

# Token display
TOKEN_DISPLAY_PREFIX_LENGTH = 8
