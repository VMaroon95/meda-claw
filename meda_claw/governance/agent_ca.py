"""
meda-claw v4.0 Governance Fabric
Agent Certificate Authority
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional


MEDACLAW_DIR = Path.home() / ".medaclaw"


@dataclass
class AgentCertificate:
    agent_id: str
    name: str
    owner: str
    capabilities: List[str]
    issued_at: str
    expires_at: str
    ca_signature: str
    cert_hash: str
    revoked: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "AgentCertificate":
        return cls(**d)


class AgentCA:
    def __init__(self):
        MEDACLAW_DIR.mkdir(parents=True, exist_ok=True)
        self._key_path = MEDACLAW_DIR / "ca_master.key"
        self._registry_path = MEDACLAW_DIR / "agent_registry.json"
        self._master_key = self._load_or_create_key()
        self._registry = self._load_registry()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_or_create_key(self) -> bytes:
        if self._key_path.exists():
            return self._key_path.read_bytes()
        key = secrets.token_bytes(32)
        self._key_path.write_bytes(key)
        self._key_path.chmod(0o600)
        return key

    def _load_registry(self) -> dict:
        if self._registry_path.exists():
            try:
                return json.loads(self._registry_path.read_text())
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save_registry(self) -> None:
        self._registry_path.write_text(json.dumps(self._registry, indent=2))

    def _sign(self, payload: str) -> str:
        sig = hmac.new(self._master_key, payload.encode(), hashlib.sha256)
        return sig.hexdigest()

    def _cert_payload(self, cert: AgentCertificate) -> str:
        return json.dumps(
            {
                "agent_id": cert.agent_id,
                "name": cert.name,
                "owner": cert.owner,
                "capabilities": sorted(cert.capabilities),
                "issued_at": cert.issued_at,
                "expires_at": cert.expires_at,
            },
            sort_keys=True,
        )

    def _cert_hash(self, cert: AgentCertificate) -> str:
        payload = self._cert_payload(cert)
        return hashlib.sha256(payload.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(
        self,
        name: str,
        owner: str,
        capabilities: List[str],
        expires_days: int = 365,
    ) -> AgentCertificate:
        agent_id = secrets.token_hex(16)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=expires_days)

        cert = AgentCertificate(
            agent_id=agent_id,
            name=name,
            owner=owner,
            capabilities=list(capabilities),
            issued_at=now.isoformat(),
            expires_at=expires.isoformat(),
            ca_signature="",
            cert_hash="",
        )

        payload = self._cert_payload(cert)
        cert.ca_signature = self._sign(payload)
        cert.cert_hash = self._cert_hash(cert)

        self._registry[agent_id] = cert.to_dict()
        self._save_registry()
        return cert

    def verify(self, cert: AgentCertificate) -> bool:
        if cert.revoked:
            return False
        # Check expiry
        try:
            expires = datetime.fromisoformat(cert.expires_at)
            if expires < datetime.now(timezone.utc):
                return False
        except ValueError:
            return False
        # Verify HMAC signature
        expected_sig = self._sign(self._cert_payload(cert))
        if not hmac.compare_digest(cert.ca_signature, expected_sig):
            return False
        # Verify hash
        expected_hash = self._cert_hash(cert)
        return hmac.compare_digest(cert.cert_hash, expected_hash)

    def verify_by_id(self, agent_id: str) -> bool:
        entry = self._registry.get(agent_id)
        if entry is None:
            return False
        cert = AgentCertificate.from_dict(entry)
        return self.verify(cert)

    def revoke(self, agent_id: str) -> bool:
        entry = self._registry.get(agent_id)
        if entry is None:
            return False
        entry["revoked"] = True
        self._save_registry()
        return True

    def list_agents(self) -> list:
        return list(self._registry.values())

    def stats(self) -> dict:
        agents = list(self._registry.values())
        total = len(agents)
        revoked = sum(1 for a in agents if a.get("revoked", False))
        active = total - revoked
        return {"total": total, "active": active, "revoked": revoked}
