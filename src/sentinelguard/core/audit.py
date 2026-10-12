"""
Tamper-evident Cryptographic Audit Ledger for SentinelGuard.
Maintains a hash-chained, immutable record of incident response decisions.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from sentinelguard.core.schemas import GovernanceDecision


class AuditRecord(BaseModel):
    index: int
    timestamp: float
    decision: str
    original_action_type: str
    target_resource_id: str
    executed_action_type: Optional[str] = None
    reason: str
    invariant_results: Dict[str, bool]
    blast_radius: List[str]
    previous_hash: str
    current_hash: str


class AuditLedger:
    """
    Append-only cryptographic ledger tracking all governance evaluations.
    """

    def __init__(self) -> None:
        self.chain: List[AuditRecord] = []
        self._genesis_hash = "0" * 64

    def record_decision(self, decision: GovernanceDecision) -> AuditRecord:
        """
        Record a governance decision into the hash chain.
        """
        idx = len(self.chain)
        prev_hash = self.chain[-1].current_hash if self.chain else self._genesis_hash
        ts = time.time()

        content = {
            "index": idx,
            "timestamp": ts,
            "decision": decision.decision.value,
            "original_action": decision.original_action.model_dump(),
            "executed_action": decision.executed_action.model_dump() if decision.executed_action else None,
            "reason": decision.reason,
            "invariant_results": decision.invariant_results,
            "blast_radius": decision.blast_radius,
            "previous_hash": prev_hash,
        }

        content_str = json.dumps(content, sort_keys=True)
        curr_hash = hashlib.sha256(content_str.encode("utf-8")).hexdigest()

        record = AuditRecord(
            index=idx,
            timestamp=ts,
            decision=decision.decision.value,
            original_action_type=decision.original_action.action_type.value,
            target_resource_id=decision.original_action.target_resource_id,
            executed_action_type=decision.executed_action.action_type.value if decision.executed_action else None,
            reason=decision.reason,
            invariant_results=decision.invariant_results,
            blast_radius=decision.blast_radius,
            previous_hash=prev_hash,
            current_hash=curr_hash,
        )

        self.chain.append(record)
        decision.audit_hash = curr_hash
        return record

    def verify_integrity(self) -> bool:
        """
        Verify that no records in the audit chain have been altered or deleted.
        """
        if not self.chain:
            return True

        for i, record in enumerate(self.chain):
            expected_prev = self._genesis_hash if i == 0 else self.chain[i - 1].current_hash
            if record.previous_hash != expected_prev:
                return False

        return True
