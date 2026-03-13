"""
AI Governance Score — Weighted 0-100 metric.

Scoring weights:
  - Attribution (30%): AI provenance tracking, human-review attestations
  - Permissions (40%): Secret exposure, API key hygiene, credential management
  - Behavior   (30%): Agent action logging, policy compliance, configuration

Each category starts at its max weight. Findings dock points based on severity.
"""

from .findings import Finding, Severity, Category


# Severity penalties (points deducted per finding)
SEVERITY_PENALTY = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

# Category weights (must sum to 100)
CATEGORY_WEIGHTS = {
    "attribution": 30,
    "permissions": 40,
    "behavior": 30,
}

# Map finding categories to score categories
CATEGORY_MAP = {
    Category.SECRET: "permissions",
    Category.PERMISSION: "permissions",
    Category.ATTRIBUTION: "attribution",
    Category.BEHAVIOR: "behavior",
    Category.POLICY: "behavior",
    Category.CONFIGURATION: "behavior",
}


class GovernanceScorer:
    """
    Calculates the AI Governance Score (0-100).

    Higher is better. 90+ is excellent. Below 50 is failing.
    """

    def score(self, findings: list[Finding]) -> tuple[int, dict]:
        """
        Calculate governance score from findings.

        Returns:
            (score, breakdown_dict)
        """
        # Start each category at max
        category_scores = {k: v for k, v in CATEGORY_WEIGHTS.items()}
        category_findings = {k: 0 for k in CATEGORY_WEIGHTS}
        category_deductions = {k: 0 for k in CATEGORY_WEIGHTS}

        has_secret = False
        has_injection = False

        for finding in findings:
            cat = CATEGORY_MAP.get(finding.category, "behavior")
            penalty = SEVERITY_PENALTY.get(finding.severity, 0)
            category_deductions[cat] += penalty
            category_findings[cat] += 1

            # Track critical threat classes
            if finding.category == Category.SECRET and finding.severity == Severity.CRITICAL:
                has_secret = True
            if finding.category == Category.BEHAVIOR and finding.severity == Severity.CRITICAL:
                has_injection = True

        # Apply deductions (floor at 0 per category)
        for cat in category_scores:
            max_score = CATEGORY_WEIGHTS[cat]
            deduction = min(category_deductions[cat], max_score)
            category_scores[cat] = max_score - deduction

        total = sum(category_scores.values())

        # Punitive overrides: critical secrets/injections tank the score
        if has_secret:
            total = max(total - 40, 0)
        if has_injection:
            total = max(total - 30, 0)

        total = max(0, min(100, total))

        breakdown = {}
        for cat in CATEGORY_WEIGHTS:
            breakdown[cat] = {
                "max": CATEGORY_WEIGHTS[cat],
                "score": category_scores[cat],
                "findings": category_findings[cat],
                "deducted": category_deductions[cat],
            }

        return total, breakdown

    @staticmethod
    def grade(score: int) -> str:
        """Convert score to letter grade."""
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 50:
            return "D"
        return "F"

    @staticmethod
    def rating(score: int) -> str:
        """Human-readable rating."""
        if score >= 90:
            return "Excellent — production-ready governance"
        if score >= 80:
            return "Good — minor issues to address"
        if score >= 70:
            return "Fair — several governance gaps"
        if score >= 50:
            return "Poor — significant risks detected"
        return "Failing — critical governance failures"
