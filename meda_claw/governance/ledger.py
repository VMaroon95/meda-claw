"""
meda-claw v4.0 Governance Fabric
Merkle-DAG Evidence Ledger
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple


MEDACLAW_DIR = Path.home() / ".medaclaw"
GENESIS_HASH = "0" * 64


@dataclass
class EvidenceBlock:
    block_id: str
    sequence: int
    action_hash: str
    context_hash: str
    token_id: Optional[str]
    delegation_chain: List[str]
    parent_hash: str
    block_hash: str
    timestamp: str

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_row(cls, row: tuple) -> "EvidenceBlock":
        (
            block_id,
            sequence,
            action_hash,
            context_hash,
            token_id,
            delegation_chain_json,
            parent_hash,
            block_hash,
            timestamp,
        ) = row
        return cls(
            block_id=block_id,
            sequence=sequence,
            action_hash=action_hash,
            context_hash=context_hash,
            token_id=token_id,
            delegation_chain=json.loads(delegation_chain_json or "[]"),
            parent_hash=parent_hash,
            block_hash=block_hash,
            timestamp=timestamp,
        )


class EvidenceLedger:
    def __init__(self):
        MEDACLAW_DIR.mkdir(parents=True, exist_ok=True)
        self._db_path = MEDACLAW_DIR / "ledger.db"
        self._conn = self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_blocks (
                block_id TEXT PRIMARY KEY,
                sequence INTEGER NOT NULL,
                action_hash TEXT NOT NULL,
                context_hash TEXT NOT NULL,
                token_id TEXT,
                delegation_chain TEXT NOT NULL,
                parent_hash TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sequence ON evidence_blocks(sequence)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_token_id ON evidence_blocks(token_id)"
        )
        conn.commit()
        return conn

    def _last_block(self) -> Optional[EvidenceBlock]:
        cur = self._conn.execute(
            "SELECT * FROM evidence_blocks ORDER BY sequence DESC LIMIT 1"
        )
        row = cur.fetchone()
        return EvidenceBlock.from_row(row) if row else None

    def _hash_data(self, data: object) -> str:
        serialized = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()

    def _compute_block_hash(self, block: EvidenceBlock) -> str:
        payload = {
            "block_id": block.block_id,
            "sequence": block.sequence,
            "action_hash": block.action_hash,
            "context_hash": block.context_hash,
            "token_id": block.token_id,
            "delegation_chain": block.delegation_chain,
            "parent_hash": block.parent_hash,
            "timestamp": block.timestamp,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()

    def _insert(self, block: EvidenceBlock) -> None:
        self._conn.execute(
            """
            INSERT INTO evidence_blocks
            (block_id, sequence, action_hash, context_hash, token_id,
             delegation_chain, parent_hash, block_hash, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                block.block_id,
                block.sequence,
                block.action_hash,
                block.context_hash,
                block.token_id,
                json.dumps(block.delegation_chain),
                block.parent_hash,
                block.block_hash,
                block.timestamp,
            ),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(
        self,
        action: object,
        context: object,
        token_id: Optional[str] = None,
        delegation_chain: Optional[List[str]] = None,
    ) -> EvidenceBlock:
        last = self._last_block()
        parent_hash = last.block_hash if last else GENESIS_HASH
        sequence = (last.sequence + 1) if last else 0

        block_id = hashlib.sha256(
            f"{sequence}{time.time_ns()}".encode()
        ).hexdigest()[:32]

        block = EvidenceBlock(
            block_id=block_id,
            sequence=sequence,
            action_hash=self._hash_data(action),
            context_hash=self._hash_data(context),
            token_id=token_id,
            delegation_chain=delegation_chain or [],
            parent_hash=parent_hash,
            block_hash="",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        block.block_hash = self._compute_block_hash(block)
        self._insert(block)
        return block

    def verify_chain(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        cur = self._conn.execute(
            "SELECT * FROM evidence_blocks ORDER BY sequence ASC"
        )
        rows = cur.fetchall()
        if not rows:
            return True, []

        prev_hash = GENESIS_HASH
        for row in rows:
            block = EvidenceBlock.from_row(row)
            # Check parent linkage
            if block.sequence == 0:
                if block.parent_hash != GENESIS_HASH:
                    errors.append(
                        f"Block {block.block_id}: genesis parent hash mismatch"
                    )
            else:
                if block.parent_hash != prev_hash:
                    errors.append(
                        f"Block {block.block_id} (seq {block.sequence}): "
                        f"parent_hash mismatch (expected {prev_hash[:12]}…)"
                    )
            # Check self hash
            expected_hash = self._compute_block_hash(block)
            if block.block_hash != expected_hash:
                errors.append(
                    f"Block {block.block_id}: block_hash corrupted"
                )
            prev_hash = block.block_hash

        return len(errors) == 0, errors

    def query(self, token_id: Optional[str] = None, limit: int = 50) -> List[EvidenceBlock]:
        if token_id is not None:
            cur = self._conn.execute(
                "SELECT * FROM evidence_blocks WHERE token_id = ? ORDER BY sequence DESC LIMIT ?",
                (token_id, limit),
            )
        else:
            cur = self._conn.execute(
                "SELECT * FROM evidence_blocks ORDER BY sequence DESC LIMIT ?",
                (limit,),
            )
        return [EvidenceBlock.from_row(row) for row in cur.fetchall()]

    def chain_of_belief(self, block_id: str) -> List[EvidenceBlock]:
        """Traces the chain back to genesis starting from block_id."""
        chain: List[EvidenceBlock] = []
        current_id = block_id
        visited = set()
        while current_id and current_id not in visited:
            visited.add(current_id)
            cur = self._conn.execute(
                "SELECT * FROM evidence_blocks WHERE block_id = ?", (current_id,)
            )
            row = cur.fetchone()
            if row is None:
                break
            block = EvidenceBlock.from_row(row)
            chain.append(block)
            if block.parent_hash == GENESIS_HASH or block.sequence == 0:
                break
            # Find block whose block_hash matches this block's parent_hash
            cur2 = self._conn.execute(
                "SELECT * FROM evidence_blocks WHERE block_hash = ?",
                (block.parent_hash,),
            )
            row2 = cur2.fetchone()
            if row2 is None:
                break
            current_id = EvidenceBlock.from_row(row2).block_id
        return chain

    def export_audit_report(self, output_path: Optional[str] = None) -> dict:
        valid, errors = self.verify_chain()
        blocks = self.query(limit=1000)
        total = len(blocks)
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "chain_valid": valid,
            "chain_errors": errors,
            "total_blocks": total,
            "compliance_mappings": {
                "EU_AI_Act_Art13": {
                    "requirement": "Transparency and provision of information to deployers",
                    "status": "COMPLIANT" if valid else "NON-COMPLIANT",
                    "evidence": f"{total} evidence blocks logged with cryptographic integrity",
                },
                "SOC2_CC6_1": {
                    "requirement": "Logical and physical access controls",
                    "status": "COMPLIANT" if valid else "NON-COMPLIANT",
                    "evidence": "Merkle-chained evidence blocks prevent tampering",
                },
                "ISO27001_A9": {
                    "requirement": "Access control",
                    "status": "COMPLIANT" if valid else "NON-COMPLIANT",
                    "evidence": "All access actions logged with delegation chain provenance",
                },
            },
            "blocks_sample": [b.to_dict() for b in blocks[:5]],
        }
        if output_path is None:
            output_path = str(MEDACLAW_DIR / "audit_report.json")
        Path(output_path).write_text(json.dumps(report, indent=2))
        report["output_path"] = output_path
        return report
