"""
Behavior Scanner — Configuration and policy compliance checks.

Validates project governance posture: config presence, policy
settings, dependency hygiene, and security configurations.
"""

import json
import os
from pathlib import Path

from ..core.findings import Finding, Severity, Category


# Known vulnerable or suspicious npm packages
SUSPICIOUS_NPM = {
    "event-stream": "Known supply chain attack vector",
    "flatmap-stream": "Malicious package (cryptocurrency theft)",
    "ua-parser-js": "Compromised package (crypto mining)",
    "coa": "Compromised package (credential theft)",
    "rc": "Compromised package",
}

# Dangerous Python imports
DANGEROUS_IMPORTS = {
    r"pickle\.loads": "Deserialization can execute arbitrary code",
    r"eval\(": "Arbitrary code execution risk",
    r"exec\(": "Arbitrary code execution risk",
    r"subprocess\.call\(.*shell\s*=\s*True": "Shell injection risk",
    r"__import__\(": "Dynamic imports can be exploited",
}


class BehaviorScanner:
    """Scans for behavioral and configuration risks."""

    name = "behavior_scanner"
    version = "1.0.0"

    def scan(self, target: str) -> list[Finding]:
        findings = []
        target_path = Path(target).resolve()

        findings.extend(self._check_governance_config(target_path))
        findings.extend(self._check_gitignore(target_path))
        findings.extend(self._check_dependencies(target_path))
        findings.extend(self._check_dangerous_patterns(target_path))

        return findings

    def _check_governance_config(self, target_path: Path) -> list[Finding]:
        """Check for meda-claw governance configuration."""
        config = target_path / ".medaclaw.json"
        if not config.exists():
            return [Finding(
                category=Category.CONFIGURATION,
                severity=Severity.LOW,
                rule="config/no_governance_config",
                message="No .medaclaw.json governance configuration",
                remediation="Run `medaclaw init` to create governance config.",
            )]

        # Validate config structure
        try:
            with open(config) as f:
                data = json.load(f)
            if "modules" not in data:
                return [Finding(
                    category=Category.CONFIGURATION,
                    severity=Severity.MEDIUM,
                    rule="config/invalid_config",
                    message=".medaclaw.json is missing 'modules' configuration",
                    remediation="Run `medaclaw init` to regenerate config.",
                )]
        except (json.JSONDecodeError, OSError):
            return [Finding(
                category=Category.CONFIGURATION,
                severity=Severity.MEDIUM,
                rule="config/malformed_config",
                message=".medaclaw.json is malformed",
                remediation="Delete and run `medaclaw init` to regenerate.",
            )]

        return []

    def _check_gitignore(self, target_path: Path) -> list[Finding]:
        """Check if .gitignore excludes sensitive files."""
        findings = []
        gitignore = target_path / ".gitignore"

        if not gitignore.exists():
            if (target_path / ".git").exists():
                return [Finding(
                    category=Category.POLICY,
                    severity=Severity.MEDIUM,
                    rule="policy/no_gitignore",
                    message="No .gitignore file in git repository",
                    remediation="Add .gitignore with entries for .env, credentials, and build artifacts.",
                )]
            return []

        content = gitignore.read_text(errors="ignore")
        sensitive = [".env", "*.pem", "*.key", "credentials"]
        missing = [s for s in sensitive if s not in content]

        if missing:
            findings.append(Finding(
                category=Category.POLICY,
                severity=Severity.MEDIUM,
                rule="policy/gitignore_incomplete",
                message=f".gitignore missing entries for: {', '.join(missing)}",
                remediation=f"Add these to .gitignore: {', '.join(missing)}",
            ))

        return findings

    def _check_dependencies(self, target_path: Path) -> list[Finding]:
        """Check for known suspicious dependencies."""
        findings = []

        # npm
        pkg_json = target_path / "package.json"
        if pkg_json.exists():
            try:
                with open(pkg_json) as f:
                    pkg = json.load(f)
                all_deps = {}
                all_deps.update(pkg.get("dependencies", {}))
                all_deps.update(pkg.get("devDependencies", {}))

                for dep, reason in SUSPICIOUS_NPM.items():
                    if dep in all_deps:
                        findings.append(Finding(
                            category=Category.BEHAVIOR,
                            severity=Severity.CRITICAL,
                            rule=f"deps/suspicious_npm_{dep}",
                            message=f"Suspicious npm package: {dep} — {reason}",
                            file="package.json",
                            remediation=f"Remove {dep} and audit your dependency tree.",
                        ))
            except (json.JSONDecodeError, OSError):
                pass

        return findings

    def _check_dangerous_patterns(self, target_path: Path) -> list[Finding]:
        """Check for dangerous code patterns in Python files."""
        import re
        findings = []
        skip = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "test", "tests"}

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in skip]
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = Path(root) / fname
                try:
                    content = fpath.read_text(errors="ignore")
                except (OSError, PermissionError):
                    continue

                for pattern_str, reason in DANGEROUS_IMPORTS.items():
                    if re.search(pattern_str, content):
                        rel_path = str(fpath.relative_to(target_path))
                        findings.append(Finding(
                            category=Category.BEHAVIOR,
                            severity=Severity.MEDIUM,
                            rule=f"behavior/dangerous_pattern",
                            message=f"Dangerous pattern '{pattern_str}' in {rel_path}: {reason}",
                            file=rel_path,
                            remediation=f"Review usage of {pattern_str}. Ensure it's necessary and input-validated.",
                        ))

        return findings
