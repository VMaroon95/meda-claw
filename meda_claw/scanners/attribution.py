"""
Attribution Scanner — Detects AI-generated code without provenance.

Scans for AI generation markers, missing attribution headers,
and unsigned AI-heavy commits. Part of the Governance Score
attribution layer (30% weight).
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from ..core.findings import Finding, Severity, Category


# Patterns indicating AI-generated code
AI_MARKERS = [
    re.compile(r"(?i)generated\s+by\s+(claude|gpt|copilot|codex|gemini|llama|mistral|ai[_\-\s]?agent)", re.IGNORECASE),
    re.compile(r"(?i)this\s+(?:code|file|function)\s+was\s+(?:generated|created|written)\s+(?:by|with|using)\s+(?:ai|claude|gpt|copilot|chatgpt)", re.IGNORECASE),
    re.compile(r"(?i)#\s*ai[_\-\s]?generated", re.IGNORECASE),
    re.compile(r"(?i)//\s*auto[_\-\s]?generated\s+by", re.IGNORECASE),
    re.compile(r"(?i)@generated\s+by", re.IGNORECASE),
    re.compile(r"(?i)(?:refactored|rewritten|optimized|patched)\s+by\s+(?:ai|claude|gpt|copilot|agent)", re.IGNORECASE),
    re.compile(r"(?i)AI[_\-\s]?Agent[_\-\s]?[A-Z0-9]", re.IGNORECASE),
    re.compile(r"(?i)(?:forensic\s+metadata|purpose):\s*.*(?:ai|agent|generated|refactor)", re.IGNORECASE),
]

# Source file extensions
SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
    ".php", ".rs", ".c", ".cpp", ".h", ".cs", ".swift", ".kt",
}


class AttributionScanner:
    """Scans for AI attribution issues and missing provenance."""

    name = "attribution_scanner"
    version = "1.0.0"

    def scan(self, target: str) -> list[Finding]:
        findings = []
        target_path = Path(target).resolve()

        # Check for AI markers without attestation
        findings.extend(self._scan_ai_markers(target_path))

        # Check attestation coverage
        findings.extend(self._check_attestations(target_path))

        # Check for LICENSE file
        findings.extend(self._check_license(target_path))

        # Check git provenance hooks
        findings.extend(self._check_provenance_hooks(target_path))

        return findings

    def _scan_ai_markers(self, target_path: Path) -> list[Finding]:
        """Find files with AI generation markers."""
        findings = []
        skip = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in skip]
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix not in SOURCE_EXTENSIONS:
                    continue
                try:
                    content = fpath.read_text(errors="ignore")
                except (OSError, PermissionError):
                    continue

                for pattern in AI_MARKERS:
                    match = pattern.search(content)
                    if match:
                        line_num = content[:match.start()].count("\n") + 1
                        rel_path = str(fpath.relative_to(target_path))
                        findings.append(Finding(
                            category=Category.ATTRIBUTION,
                            severity=Severity.MEDIUM,
                            rule="attribution/ai_generated_no_attestation",
                            message=f"AI-generated code marker found without attestation: {rel_path}:{line_num}",
                            file=rel_path,
                            line=line_num,
                            evidence=match.group(0)[:60],
                            remediation="Run `medaclaw sign` to create a Human-Review Attestation for this code.",
                        ))
                        break  # One finding per file

        return findings

    def _check_attestations(self, target_path: Path) -> list[Finding]:
        """Check if the project has attestation coverage."""
        manifest = target_path / ".medaclaw-attestations.jsonl"
        if not manifest.exists():
            return [Finding(
                category=Category.ATTRIBUTION,
                severity=Severity.LOW,
                rule="attribution/no_attestations",
                message="No Human-Review Attestations found in project",
                remediation="Run `medaclaw sign` after reviewing AI-assisted code to create attestations.",
            )]
        return []

    def _check_license(self, target_path: Path) -> list[Finding]:
        """Check for license file."""
        license_files = list(target_path.glob("LICENSE*")) + list(target_path.glob("LICENCE*"))
        if not license_files:
            return [Finding(
                category=Category.ATTRIBUTION,
                severity=Severity.MEDIUM,
                rule="attribution/no_license",
                message="No LICENSE file found — IP ownership unclear",
                remediation="Add a LICENSE file to clarify IP ownership and usage terms.",
            )]
        return []

    def _check_provenance_hooks(self, target_path: Path) -> list[Finding]:
        """Check if git provenance hooks are installed."""
        git_dir = target_path / ".git"
        if not git_dir.exists():
            return []

        pre_commit = git_dir / "hooks" / "pre-commit"
        if not pre_commit.exists() or "medaclaw" not in pre_commit.read_text(errors="ignore"):
            return [Finding(
                category=Category.ATTRIBUTION,
                severity=Severity.LOW,
                rule="attribution/no_hooks",
                message="No meda-claw pre-commit hooks installed",
                remediation="Run `medaclaw init` to install governance hooks.",
            )]
        return []
