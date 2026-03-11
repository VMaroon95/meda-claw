"""
Semantic Reviewer — Critical path analysis and reasoning traces.

Analyzes findings against governance_rules.json to determine business impact.
Produces human-readable reasoning traces explaining WHY a finding matters,
not just WHAT was found. Designed for PR review dashboards.

No external API calls. All analysis is rule-based and deterministic.
"""

import fnmatch
import json
import re
from pathlib import Path
from typing import Optional

from .findings import Finding, Severity, Category


# Load governance rules
RULES_PATH = Path(__file__).parent.parent / "policy" / "governance_rules.json"


def _load_rules() -> dict:
    if RULES_PATH.exists():
        with open(RULES_PATH) as f:
            return json.load(f)
    return {"critical_paths": {}, "high_risk_tokens": [], "scoring_multipliers": {}}


class SemanticReviewer:
    """
    Analyzes findings for business-critical impact using governance rules.

    Produces:
    1. Critical path classifications (auth/db/infra/financial)
    2. Risk multiplier adjustments for high-impact areas
    3. Reasoning traces explaining each finding's business context
    """

    def __init__(self):
        self.rules = _load_rules()
        self.critical_paths = self.rules.get("critical_paths", {})
        self.high_risk_tokens = self.rules.get("high_risk_tokens", [])
        self.multipliers = self.rules.get("scoring_multipliers", {})

    def review(self, findings: list[Finding]) -> dict:
        """
        Run semantic review on findings.

        Returns:
            {
                "critical_findings": [...],
                "path_classifications": {...},
                "adjusted_findings": [...],
                "reasoning_trace": "...",
                "risk_escalations": int,
            }
        """
        critical = []
        classifications = {}
        escalations = 0
        traces = []

        for finding in findings:
            # Classify by critical path
            path_class = self._classify_path(finding.file) if finding.file else None

            if path_class:
                classifications[finding.file or "unknown"] = path_class
                multiplier_key = {
                    "authentication": "auth_violation",
                    "database": "db_schema_change",
                    "infrastructure": "infra_mutation",
                    "financial_gateways": "auth_violation",
                }.get(path_class)

                multiplier = self.multipliers.get(multiplier_key, 1.0)

                # Escalate severity if in critical path
                if finding.severity in (Severity.MEDIUM, Severity.LOW) and multiplier > 1.5:
                    escalated = Finding(
                        category=finding.category,
                        severity=Severity.HIGH,
                        rule=finding.rule,
                        message=f"[ESCALATED — {path_class}] {finding.message}",
                        file=finding.file,
                        line=finding.line,
                        evidence=finding.evidence,
                        remediation=finding.remediation,
                        metadata={**finding.metadata, "escalated_from": finding.severity.value,
                                  "critical_path": path_class, "multiplier": multiplier},
                    )
                    critical.append(escalated)
                    escalations += 1
                    traces.append(self._generate_trace(escalated, path_class, multiplier))
                else:
                    if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                        critical.append(finding)
                        traces.append(self._generate_trace(finding, path_class, multiplier))
            else:
                # Check for high-risk tokens in evidence
                token_match = self._check_high_risk_tokens(finding)
                if token_match and finding.severity in (Severity.CRITICAL, Severity.HIGH):
                    critical.append(finding)
                    traces.append(
                        f"⚠ {finding.rule}: High-risk token '{token_match}' detected. "
                        f"{finding.message}"
                    )

        # Build combined reasoning trace
        reasoning = self._build_reasoning_trace(findings, critical, classifications, escalations)

        return {
            "critical_findings": [f.to_dict() for f in critical],
            "path_classifications": classifications,
            "risk_escalations": escalations,
            "reasoning_trace": reasoning,
            "finding_traces": traces,
        }

    def _classify_path(self, file_path: Optional[str]) -> Optional[str]:
        """Classify a file path into a critical business domain."""
        if not file_path:
            return None

        for domain, patterns in self.critical_paths.items():
            for pattern in patterns:
                if fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(f"**/{file_path}", pattern):
                    return domain
                # Also check if any path component matches
                if any(fnmatch.fnmatch(part, pattern.replace("**/", ""))
                       for part in Path(file_path).parts):
                    return domain
        return None

    def _check_high_risk_tokens(self, finding: Finding) -> Optional[str]:
        """Check if a finding's evidence contains high-risk tokens."""
        evidence = (finding.evidence or "") + " " + (finding.message or "")
        for token in self.high_risk_tokens:
            if token.lower() in evidence.lower():
                return token
        return None

    def _generate_trace(self, finding: Finding, path_class: str, multiplier: float) -> str:
        """Generate a reasoning trace for a single finding."""
        impact = {
            "authentication": "Authentication bypass or credential exposure can lead to full account takeover",
            "database": "Database modifications can cause data loss, corruption, or unauthorized access",
            "infrastructure": "Infrastructure changes can expose the entire deployment to attack",
            "financial_gateways": "Payment system exposure creates direct financial liability",
        }.get(path_class, "Potential security impact")

        return (
            f"🔍 {finding.rule} in {finding.file or 'unknown'}\n"
            f"   Domain: {path_class} (multiplier: {multiplier}x)\n"
            f"   Impact: {impact}\n"
            f"   Action: {finding.remediation or 'Review required'}"
        )

    def _build_reasoning_trace(
        self,
        all_findings: list[Finding],
        critical: list[Finding],
        classifications: dict,
        escalations: int,
    ) -> str:
        """Build the complete reasoning trace summary."""
        lines = [
            "═══ SEMANTIC REVIEW — REASONING TRACE ═══",
            "",
            f"Total findings analyzed: {len(all_findings)}",
            f"Critical/high-impact:   {len(critical)}",
            f"Risk escalations:       {escalations}",
            f"Critical paths touched:  {len(set(classifications.values()))}",
            "",
        ]

        if classifications:
            lines.append("Critical Path Classifications:")
            by_domain = {}
            for file, domain in classifications.items():
                by_domain.setdefault(domain, []).append(file)
            for domain, files in by_domain.items():
                lines.append(f"  [{domain.upper()}]")
                for f in files[:5]:
                    lines.append(f"    → {f}")
                if len(files) > 5:
                    lines.append(f"    ... and {len(files) - 5} more")
            lines.append("")

        if critical:
            lines.append("Priority Actions:")
            for i, f in enumerate(critical[:5], 1):
                lines.append(f"  {i}. {f.message}")
                if f.remediation:
                    lines.append(f"     → {f.remediation}")
        else:
            lines.append("No critical-path violations detected.")

        lines.extend(["", "═══ END TRACE ═══"])
        return "\n".join(lines)
