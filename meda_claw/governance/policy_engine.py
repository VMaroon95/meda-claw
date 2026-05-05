"""
meda-claw v4.0 Governance Fabric
Delegation Token Policy Engine
"""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional


MEDACLAW_DIR = Path.home() / ".medaclaw"


class PolicyViolation(Exception):
    """Raised when a policy check fails."""


@dataclass
class DelegationToken:
    token_id: str
    issuer_id: str
    subject_id: str
    scope: List[str]
    issued_at: str
    expires_at: str
    parent_token_id: Optional[str] = None
    revoked: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "DelegationToken":
        return cls(**d)


class PolicyEngine:
    def __init__(self):
        MEDACLAW_DIR.mkdir(parents=True, exist_ok=True)
        self._tokens_path = MEDACLAW_DIR / "tokens.json"
        self._decisions_path = MEDACLAW_DIR / "policy_decisions.jsonl"
        self._tokens: dict = self._load_tokens()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_tokens(self) -> dict:
        if self._tokens_path.exists():
            try:
                return json.loads(self._tokens_path.read_text())
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save_tokens(self) -> None:
        self._tokens_path.write_text(json.dumps(self._tokens, indent=2))

    def _log_decision(self, decision: dict) -> None:
        try:
            with self._decisions_path.open("a") as fh:
                fh.write(json.dumps(decision) + "\n")
        except OSError:
            pass

    def _is_token_valid(self, token: DelegationToken) -> bool:
        if token.revoked:
            return False
        try:
            expires = datetime.fromisoformat(token.expires_at)
            if expires < datetime.now(timezone.utc):
                return False
        except ValueError:
            return False
        return True

    def _get_token(self, token_id: str) -> Optional[DelegationToken]:
        entry = self._tokens.get(token_id)
        if entry is None:
            return None
        return DelegationToken.from_dict(entry)

    def _parent_scope(self, parent_token_id: str) -> List[str]:
        parent = self._get_token(parent_token_id)
        if parent is None or not self._is_token_valid(parent):
            raise PolicyViolation(
                f"Parent token {parent_token_id} is invalid or expired"
            )
        return parent.scope

    def _is_restricted_hours(self) -> bool:
        """Returns True if current local time is after 21:00 or before 07:00."""
        hour = datetime.now().hour
        return hour >= 21 or hour < 7

    def _action_matches_scope(self, action: str, resource: str, scope: List[str]) -> bool:
        """
        Scope entries can be:
          - exact: "read:/data/file"
          - action wildcard: "read:*"
          - full wildcard: "*"
        """
        target = f"{action}:{resource}"
        for s in scope:
            if s == "*":
                return True
            if s == target:
                return True
            if s.endswith(":*") and s[:-2] == action:
                return True
            if ":" not in s and s == action:
                return True
        return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def issue_token(
        self,
        issuer_id: str,
        subject_id: str,
        scope: List[str],
        expires_hours: int = 24,
        parent_token_id: Optional[str] = None,
    ) -> DelegationToken:
        if parent_token_id is not None:
            parent_scope = self._parent_scope(parent_token_id)
            for s in scope:
                if s not in parent_scope and "*" not in parent_scope:
                    raise PolicyViolation(
                        f"Child scope '{s}' not in parent scope {parent_scope}"
                    )

        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=expires_hours)
        token = DelegationToken(
            token_id=secrets.token_hex(16),
            issuer_id=issuer_id,
            subject_id=subject_id,
            scope=list(scope),
            issued_at=now.isoformat(),
            expires_at=expires.isoformat(),
            parent_token_id=parent_token_id,
        )
        self._tokens[token.token_id] = token.to_dict()
        self._save_tokens()
        return token

    def revoke_token(self, token_id: str) -> bool:
        entry = self._tokens.get(token_id)
        if entry is None:
            return False
        entry["revoked"] = True
        self._save_tokens()
        return True

    def check(self, agent_id: str, action: str, resource: str) -> bool:
        """Returns True if agent has a valid token covering action on resource."""
        for token_data in self._tokens.values():
            token = DelegationToken.from_dict(token_data)
            if token.subject_id != agent_id:
                continue
            if not self._is_token_valid(token):
                continue
            if self._action_matches_scope(action, resource, token.scope):
                return True
        return False

    def governance_loop(self, agent_id: str, action: str, resource: str) -> dict:
        """
        Runs four governance checks and returns a result dict.
        Steps: Identity, Permission, Compliance, Consent
        """
        result = {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "identity": False,
            "permission": False,
            "compliance": False,
            "consent": False,
            "allowed": False,
            "reason": "",
        }

        # 1. Identity: agent has at least one non-revoked token
        has_token = any(
            DelegationToken.from_dict(t).subject_id == agent_id
            and not DelegationToken.from_dict(t).revoked
            for t in self._tokens.values()
        )
        result["identity"] = has_token
        if not has_token:
            result["reason"] = "No valid identity token found"
            self._log_decision(result)
            return result

        # 2. Permission: default policy + token check
        permission = False
        if action == "read":
            permission = True  # reads always allowed by default
        elif action in ("write",):
            if self._is_restricted_hours():
                permission = self.check(agent_id, action, resource)
                if not permission:
                    result["reason"] = "Write blocked outside business hours without token"
            else:
                permission = True
        elif action in ("delete", "execute"):
            permission = self.check(agent_id, action, resource)
        else:
            permission = self.check(agent_id, action, resource)

        result["permission"] = permission
        if not permission:
            if not result["reason"]:
                result["reason"] = f"No token grants {action} on {resource}"
            self._log_decision(result)
            return result

        # 3. Compliance: restricted actions require an explicit token
        if action in ("delete", "execute"):
            compliant = self.check(agent_id, action, resource)
        else:
            compliant = True
        result["compliance"] = compliant
        if not compliant:
            result["reason"] = f"Compliance check failed: {action} requires explicit delegation"
            self._log_decision(result)
            return result

        # 4. Consent: token must have been explicitly issued (not implied)
        if action in ("delete", "execute", "write"):
            consent = self.check(agent_id, action, resource)
        else:
            consent = True
        result["consent"] = consent
        if not consent:
            result["reason"] = "Consent not granted via delegation token"
            self._log_decision(result)
            return result

        result["allowed"] = True
        result["reason"] = "All governance checks passed"
        self._log_decision(result)
        return result

    def load_policy_decisions(self, limit: int = 50) -> list:
        if not self._decisions_path.exists():
            return []
        try:
            lines = self._decisions_path.read_text().strip().splitlines()
            decisions = [json.loads(l) for l in lines if l.strip()]
            return decisions[-limit:]
        except (json.JSONDecodeError, OSError):
            return []
