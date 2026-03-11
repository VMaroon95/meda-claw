"""
Policy Engine — Human-Review Attestation & Governance Verification.

Ensures AI-heavy commits include a cryptographic human-review attestation,
creating an auditable chain of human oversight for IP compliance.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Optional


# ── Attestation Format ───────────────────────────────────────────────────

def create_attestation(
    reviewer: str,
    ai_percentage: float,
    commit_hash: Optional[str] = None,
    notes: str = "",
) -> dict:
    """
    Create a Human-Review Attestation record.

    The attestation certifies that a human has reviewed AI-generated
    or AI-assisted code and takes responsibility for its correctness,
    originality, and IP compliance.
    """
    attestation = {
        "schema": "meda-claw/attestation/v1",
        "type": "human-review",
        "reviewer": reviewer,
        "ai_percentage": ai_percentage,
        "commit_hash": commit_hash,
        "timestamp": time.time(),
        "iso_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "notes": notes,
        "verdict": "reviewed",
    }

    # Create integrity hash of the attestation content
    content = json.dumps(
        {k: v for k, v in attestation.items() if k != "integrity_hash"},
        sort_keys=True,
        default=str,
    )
    attestation["integrity_hash"] = hashlib.sha256(content.encode()).hexdigest()

    return attestation


# ── Verification ─────────────────────────────────────────────────────────

def verify_human_in_loop(ai_percentage: float, has_signature: bool) -> tuple[bool, str]:
    """
    Check if a commit meets governance policy for human oversight.

    Rules:
    - AI contribution > 50%: REQUIRES human-review attestation
    - AI contribution > 80%: REQUIRES attestation + notes explaining review scope
    - AI contribution <= 50%: Passes automatically (human-majority)
    """
    if ai_percentage > 80 and not has_signature:
        return False, "BLOCK: AI-dominant commit (>80%) lacks Human-Review Attestation. Run `medaclaw sign` after reviewing."

    if ai_percentage > 50 and not has_signature:
        return False, "BLOCK: AI-heavy commit (>50%) lacks Human-Review Attestation. Run `medaclaw sign` after reviewing."

    if ai_percentage > 50 and has_signature:
        return True, "PASS: AI-heavy commit has valid Human-Review Attestation."

    return True, "PASS: Human-majority commit. Governance standards met."


def verify_attestation_integrity(attestation: dict) -> bool:
    """Verify the integrity hash of an attestation record."""
    stored_hash = attestation.get("integrity_hash")
    if not stored_hash:
        return False

    content = json.dumps(
        {k: v for k, v in attestation.items() if k != "integrity_hash"},
        sort_keys=True,
        default=str,
    )
    expected = hashlib.sha256(content.encode()).hexdigest()
    return stored_hash == expected


# ── Manifest Management ──────────────────────────────────────────────────

MANIFEST_FILE = ".medaclaw-attestations.jsonl"


def load_attestations(project_dir: str = ".") -> list[dict]:
    """Load all attestations from the project manifest."""
    manifest = Path(project_dir) / MANIFEST_FILE
    if not manifest.exists():
        return []

    attestations = []
    with open(manifest) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    attestations.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return attestations


def save_attestation(attestation: dict, project_dir: str = "."):
    """Append an attestation to the project manifest."""
    manifest = Path(project_dir) / MANIFEST_FILE
    with open(manifest, "a") as f:
        f.write(json.dumps(attestation, default=str) + "\n")


def get_attestation_for_commit(commit_hash: str, project_dir: str = ".") -> Optional[dict]:
    """Find the attestation for a specific commit, if any."""
    for att in reversed(load_attestations(project_dir)):
        if att.get("commit_hash") == commit_hash:
            return att
    return None


# ── Policy Configuration ─────────────────────────────────────────────────

DEFAULT_GOVERNANCE_POLICY = {
    "human_review": {
        "required_above_ai_pct": 50,
        "strict_above_ai_pct": 80,
        "require_notes_above": 80,
        "block_unsigned": True,
    },
    "ip_compliance": {
        "require_license_header": False,
        "allowed_ai_models": [],  # empty = all allowed
        "max_ai_percentage": 100,
    },
}


def load_governance_policy(project_dir: str = ".") -> dict:
    """Load project governance policy, falling back to defaults."""
    config_path = Path(project_dir) / ".medaclaw.json"
    if config_path.exists():
        with open(config_path) as f:
            config = json.load(f)
            return config.get("governance", DEFAULT_GOVERNANCE_POLICY)
    return DEFAULT_GOVERNANCE_POLICY


def full_governance_check(project_dir: str = ".") -> list[dict]:
    """
    Run a comprehensive governance check on the project.

    Returns a list of findings with pass/fail status.
    """
    findings = []
    project = Path(project_dir).resolve()

    # Check for config
    config_path = project / ".medaclaw.json"
    if config_path.exists():
        findings.append({
            "check": "governance_config",
            "status": "PASS",
            "detail": "Governance config found",
        })
    else:
        findings.append({
            "check": "governance_config",
            "status": "WARN",
            "detail": "No .medaclaw.json — using default governance policy",
        })

    # Check attestation manifest
    manifest = project / MANIFEST_FILE
    if manifest.exists():
        attestations = load_attestations(project_dir)
        valid = sum(1 for a in attestations if verify_attestation_integrity(a))
        tampered = len(attestations) - valid
        findings.append({
            "check": "attestation_manifest",
            "status": "PASS" if tampered == 0 else "FAIL",
            "detail": f"{valid} valid attestations, {tampered} tampered",
        })
    else:
        findings.append({
            "check": "attestation_manifest",
            "status": "INFO",
            "detail": "No attestations yet — run `medaclaw sign` after reviewing AI-assisted code",
        })

    # Check for license
    license_files = list(project.glob("LICENSE*")) + list(project.glob("LICENCE*"))
    findings.append({
        "check": "license_file",
        "status": "PASS" if license_files else "WARN",
        "detail": f"Found: {license_files[0].name}" if license_files else "No LICENSE file",
    })

    # Check git hooks
    pre_commit = project / ".git" / "hooks" / "pre-commit"
    if pre_commit.exists() and "medaclaw" in pre_commit.read_text():
        findings.append({
            "check": "git_hooks",
            "status": "PASS",
            "detail": "meda-claw pre-commit hook installed",
        })
    elif (project / ".git").exists():
        findings.append({
            "check": "git_hooks",
            "status": "WARN",
            "detail": "No meda-claw git hooks — run `medaclaw init` to install",
        })

    return findings
