"""
Governance Engine — Orchestrates scanners, reviewer, and scoring.

Single entry point for running a complete governance audit.
Pipeline: Scan → Review → Score → Report.
"""

import time
from pathlib import Path

from .findings import AuditReport
from .scoring import GovernanceScorer
from .reviewer import SemanticReviewer
from ..scanners.secrets import SecretScanner
from ..scanners.attribution import AttributionScanner
from ..scanners.behavior import BehaviorScanner


class GovernanceEngine:
    """
    Orchestrator for the meda-claw governance audit pipeline.

    Pipeline:
    1. Run scanners (secrets, attribution, behavior)
    2. Run semantic review (critical path analysis, risk escalation)
    3. Calculate Governance Score (0-100)
    4. Produce structured AuditReport
    """

    def __init__(self, target: str):
        self.target = str(Path(target).resolve())
        self.scanners = [
            SecretScanner(),
            AttributionScanner(),
            BehaviorScanner(),
        ]
        self.scorer = GovernanceScorer()
        self.reviewer = SemanticReviewer()

    def run(self, semantic_review: bool = True) -> AuditReport:
        """
        Execute full governance audit.

        Args:
            semantic_review: If True, run critical path analysis and
                           risk escalation (adds reasoning trace to report).
        """
        start = time.time()
        report = AuditReport(target=self.target)

        # 1. Scan
        for scanner in self.scanners:
            findings = scanner.scan(self.target)
            report.findings.extend(findings)
            report.scanner_versions[scanner.name] = scanner.version

        # 2. Semantic Review
        review_data = None
        if semantic_review:
            review_data = self.reviewer.review(report.findings)
            report.review = review_data

        # 3. Score
        score, breakdown = self.scorer.score(report.findings)
        report.score = score
        report.score_breakdown = breakdown

        report.duration_ms = (time.time() - start) * 1000
        return report
