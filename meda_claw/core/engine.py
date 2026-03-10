"""
Governance Engine — Orchestrator that runs all scanners and produces scored reports.

The engine is the single entry point for running a governance audit.
It initializes scanners, collects findings, calculates the Governance Score,
and produces a structured AuditReport.
"""

import time
from pathlib import Path
from typing import Optional

from .findings import AuditReport
from .scoring import GovernanceScorer
from ..scanners.secrets import SecretScanner
from ..scanners.attribution import AttributionScanner
from ..scanners.behavior import BehaviorScanner


class GovernanceEngine:
    """
    Orchestrator for the meda-claw governance audit pipeline.

    Runs all scanners against a target, aggregates findings,
    and produces a scored AuditReport.
    """

    def __init__(self, target: str):
        self.target = str(Path(target).resolve())
        self.scanners = [
            SecretScanner(),
            AttributionScanner(),
            BehaviorScanner(),
        ]
        self.scorer = GovernanceScorer()

    def run(self) -> AuditReport:
        """
        Execute full governance audit.

        Returns:
            AuditReport with all findings and Governance Score.
        """
        start = time.time()
        report = AuditReport(target=self.target)

        # Run each scanner
        for scanner in self.scanners:
            findings = scanner.scan(self.target)
            report.findings.extend(findings)
            report.scanner_versions[scanner.name] = scanner.version

        # Score
        score, breakdown = self.scorer.score(report.findings)
        report.score = score
        report.score_breakdown = breakdown
        report.duration_ms = (time.time() - start) * 1000

        return report
