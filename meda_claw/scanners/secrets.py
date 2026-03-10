"""
Secret Scanner — Detects exposed credentials, API keys, and tokens.

Scans source files for known secret patterns. Zero network calls.
All detection is regex-based with entropy validation to reduce false positives.
"""

import math
import os
import re
from pathlib import Path
from typing import Optional

from ..core.findings import Finding, Severity, Category


# Secret patterns: (name, regex, severity, remediation)
SECRET_PATTERNS = [
    (
        "AWS Access Key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        Severity.CRITICAL,
        "Rotate the key in AWS IAM console immediately. Use environment variables or AWS Secrets Manager.",
    ),
    (
        "AWS Secret Key",
        re.compile(r"""(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?"""),
        Severity.CRITICAL,
        "Rotate in AWS IAM. Never hardcode secret keys.",
    ),
    (
        "GitHub Token",
        re.compile(r"ghp_[a-zA-Z0-9]{36}"),
        Severity.CRITICAL,
        "Revoke token at github.com/settings/tokens. Use GITHUB_TOKEN env var.",
    ),
    (
        "GitHub OAuth",
        re.compile(r"gho_[a-zA-Z0-9]{36}"),
        Severity.CRITICAL,
        "Revoke OAuth token. Use short-lived tokens.",
    ),
    (
        "OpenAI API Key",
        re.compile(r"sk-[a-zA-Z0-9]{48}"),
        Severity.CRITICAL,
        "Rotate at platform.openai.com/api-keys. Use environment variables.",
    ),
    (
        "Stripe Secret Key",
        re.compile(r"sk_live_[a-zA-Z0-9]{24,}"),
        Severity.CRITICAL,
        "Rotate in Stripe Dashboard. Use restricted keys with minimal permissions.",
    ),
    (
        "Stripe Test Key",
        re.compile(r"sk_test_[a-zA-Z0-9]{24,}"),
        Severity.MEDIUM,
        "Test keys are lower risk but should not be in source code.",
    ),
    (
        "Slack Token",
        re.compile(r"xox[bpas]-[a-zA-Z0-9\-]{10,}"),
        Severity.HIGH,
        "Revoke in Slack app settings. Use OAuth with minimal scopes.",
    ),
    (
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        Severity.HIGH,
        "Restrict key in Google Cloud Console. Add API and IP restrictions.",
    ),
    (
        "Private Key",
        re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
        Severity.CRITICAL,
        "Remove private key from source. Use a secrets manager or key vault.",
    ),
    (
        "Database Connection String",
        re.compile(r"(?:mongodb|postgres|mysql|redis|mssql):\/\/[^\s'\"]{10,}"),
        Severity.HIGH,
        "Use environment variables for connection strings. Never hardcode credentials.",
    ),
    (
        "Bearer Token",
        re.compile(r"""(?i)(?:authorization|bearer)\s*[=:]\s*['"]?bearer\s+[a-zA-Z0-9\-._~+/]{20,}=*['"]?"""),
        Severity.HIGH,
        "Remove hardcoded bearer tokens. Use runtime injection.",
    ),
    (
        "Generic High-Entropy Secret",
        re.compile(r"""(?i)(?:api[_\-]?key|secret|token|password|credential|auth)\s*[=:]\s*['"]([a-zA-Z0-9/+=\-_]{16,})['"]"""),
        Severity.MEDIUM,
        "Review if this is a real credential. Use environment variables for secrets.",
    ),
]

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".sh", ".bash", ".zsh", ".ps1", ".bat",
    ".tf", ".tfvars", ".hcl",
    ".xml", ".properties",
    ".md", ".txt", ".rst",
}

# Directories to skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".eggs", "*.egg-info", ".terraform",
}


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class SecretScanner:
    """Scans files for exposed secrets and credentials."""

    name = "secret_scanner"
    version = "1.0.0"

    def scan(self, target: str) -> list[Finding]:
        """Scan target directory for secrets. Returns list of Findings."""
        findings = []
        target_path = Path(target).resolve()

        for root, dirs, files in os.walk(target_path):
            # Prune skipped directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix not in SCAN_EXTENSIONS and fpath.name not in {".env", ".env.local", ".env.production"}:
                    continue

                try:
                    content = fpath.read_text(errors="ignore")
                except (OSError, PermissionError):
                    continue

                for name, pattern, severity, remediation in SECRET_PATTERNS:
                    for match in pattern.finditer(content):
                        matched = match.group(0)

                        # Entropy check for generic patterns to reduce false positives
                        if name == "Generic High-Entropy Secret":
                            secret_value = match.group(1) if match.lastindex else matched
                            if shannon_entropy(secret_value) < 3.5:
                                continue

                        # Calculate line number
                        line_num = content[:match.start()].count("\n") + 1

                        # Redact the evidence
                        redacted = matched[:12] + "***REDACTED***" if len(matched) > 12 else "***REDACTED***"

                        rel_path = str(fpath.relative_to(target_path))

                        findings.append(Finding(
                            category=Category.SECRET,
                            severity=severity,
                            rule=f"secret/{name.lower().replace(' ', '_')}",
                            message=f"{name} detected in {rel_path}:{line_num}",
                            file=rel_path,
                            line=line_num,
                            evidence=redacted,
                            remediation=remediation,
                            metadata={"pattern": name},
                        ))

        return findings
