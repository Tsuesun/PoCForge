# PoCForge

Generates Proof-of-Concept demonstrations from CVE fix commits. Extracts fix commits from GitHub Security Advisories and uses Claude AI to analyze the code changes, showing what was vulnerable and how it was fixed.

## Example Output

```
🚨 CVE: CVE-2025-53539
📝 Summary: fastapi-guard is vulnerable to ReDoS through inefficient regex
⚠️  Severity: MEDIUM
📅 Published: 2025-07-07 23:36:39+00:00
🔗 Advisory: https://github.com/advisories/GHSA-j47q-rc62-w448

📦 Package: fastapi-guard (pip)
   Vulnerable: <= 3.0.0
   Patched: unknown
   ✅ Found 1 fix commits from security advisory:
      🔧 Fix commit referenced in security advisory
         📄 https://github.com/rennf93/fastapi-guard/commit/d9d50e8130b7b434cdc1b001b8cfd03a06729f7f
         🏢 rennf93/fastapi-guard
         📅 Referenced in advisory
         🧪 Generated PoC (using git extraction):
            🎯 Vulnerable: fetch_azure_ip_ranges
            📋 Prerequisites: fastapi-guard <= 3.0.0 installed, Network access to download.microsoft.com, Ability to send HTTP requests to the API
            💥 Attack: ReDoS via unbounded regex pattern matching in URL parsing
            🐛 Vulnerable Code:
               pattern = r'href=["'](https://download\.microsoft\.com/' r'.*?\.json)["']'
            ✅ Fixed Code:
               pattern = r'href=["'](https://download\.microsoft\.com/.{1,500}?\.json)["']'
            🧪 Test Case:
               import re
               import time

               def test_redos():
                   # Malicious input with many characters between domain and .json
                   evil_input = 'href="https://download.microsoft.com/' + 'a' * 1000000 + '.json"'
                   
                   # Vulnerable pattern
                   vuln_pattern = r'href=["'](https://download\.microsoft\.com/.*?\.json)["']'
                   start = time.time()
                   re.search(vuln_pattern, evil_input)
                   vuln_time = time.time() - start
                   
                   # Fixed pattern
                   fixed_pattern = r'href=["'](https://download\.microsoft\.com/.{1,500}?\.json)["']'
                   start = time.time()
                   re.search(fixed_pattern, evil_input)
                   fixed_time = time.time() - start
                   
                   # Fixed version should complete much faster
                   assert fixed_time < vuln_time
            💡 Reasoning:
               The original code used an unbounded wildcard (.*?) in the regex pattern which could be exploited with a very long input string to cause catastrophic backtracking. The fix adds a specific length limit {1,500} to prevent excessive backtracking while still matching valid URLs.
```

## Setup

1. **Install:**
```bash
git clone https://github.com/Tsuesun/PoCForge.git
cd PoCForge
uv sync
```

2. **Configure API keys:**
Create `config.json`:
```json
{
  "github_token": "your_github_token",
  "anthropic_api_key": "your_claude_api_key"
}
```

3. **Run:**
```bash
uv run main.py
```

## API Keys

- **GitHub Token**: [Generate here](https://github.com/settings/tokens) (optional, for higher rate limits)
- **Claude API Key**: [Get from Anthropic](https://console.anthropic.com/) (required for PoC generation)

## How It Works

1. **Fetch CVEs** from GitHub Security Advisories
2. **Extract fix commits** directly from advisory references  
3. **Download commit diffs** to see what changed
4. **Analyze with Claude AI** to understand the vulnerability
5. **Generate PoCs** showing vulnerable vs fixed code

## Development

```bash
# Run tests
uv run pytest

# Format and lint
uv run ruff format . && uv run ruff check . && uv run mypy .
```
