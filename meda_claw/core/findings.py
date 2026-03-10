"""
Structured finding objects for governance audit results.

Every scanner produces Finding objects. The engine aggregates them.
The scorer converts them into a 0-100 Governance Score.
"""

import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SECRET = "secret"
    ATTRIBUTION = "attribution"
    PERMISSION = "permission"
    BEHAVIOR = "behavior"
    POLICY = "policy"
    CONFIGURATION = "configuration"


@dataclass
class Finding:
    """A single governance audit finding."""
    category: Category
    severity: Severity
    rule: str
    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d


@dataclass
class AuditReport:
    """Complete audit report with findings and scoring."""
    target: str
    timestamp: float = field(default_factory=time.time)
    findings: list[Finding] = field(default_factory=list)
    score: Optional[int] = None
    score_breakdown: Optional[dict] = None
    duration_ms: float = 0
    scanner_versions: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "schema": "meda-claw/report/v1",
            "target": self.target,
            "timestamp": self.timestamp,
            "iso_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)),
            "governance_score": self.score,
            "score_breakdown": self.score_breakdown,
            "duration_ms": round(self.duration_ms, 2),
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def summary(self) -> dict:
        by_severity = {}
        by_category = {}
        for f in self.findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
            by_category[f.category.value] = by_category.get(f.category.value, 0) + 1
        return {
            "total_findings": len(self.findings),
            "by_severity": by_severity,
            "by_category": by_category,
        }
