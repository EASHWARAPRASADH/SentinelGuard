"""
Execution Audit Trail for SentinelGuard (Phase 7).
Maintains a tamper-evident, SHA-256 hash-chained cryptographic ledger of the entire
execution lifecycle: from Governor decision to TOCTOU validation, dispatch, and post-verification.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExecutionAuditEntry(BaseModel):
    index: int
    timestamp: float
    stage: str  # e.g., "GOVERNOR_VERIFICATION", "APPROVAL_GATE", "TOCTOU_CHECK", "DISPATCH", "POST_VERIFICATION"
    incident_id: str
    status: str
    action_type: Optional[str] = None
    target_resource_id: Optional[str] = None
    pre_state_hash: Optional[str] = None
    post_state_hash: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    previous_hash: str
    current_hash: str


class ExecutionAuditLedger:
    """
    Append-only cryptographic ledger tracking all incident response execution transitions.
    """

    def __init__(self) -> None:
        self.chain: List[ExecutionAuditEntry] = []
        self._genesis_hash = "0" * 64

    def record_stage(
        self,
        stage: str,
        incident_id: str,
        status: str,
        action_type: Optional[str] = None,
        target_resource_id: Optional[str] = None,
        pre_state_hash: Optional[str] = None,
        post_state_hash: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ExecutionAuditEntry:
        """
        Record a lifecycle stage transition into the cryptographic chain.
        """
        idx = len(self.chain)
        prev_hash = self.chain[-1].current_hash if self.chain else self._genesis_hash
        ts = time.time()
        meta = metadata or {}

        payload = {
            "index": idx,
            "timestamp": ts,
            "stage": stage,
            "incident_id": incident_id,
            "status": status,
            "action_type": action_type,
            "target_resource_id": target_resource_id,
            "pre_state_hash": pre_state_hash,
            "post_state_hash": post_state_hash,
            "metadata": meta,
            "previous_hash": prev_hash,
        }

        payload_str = json.dumps(payload, sort_keys=True)
        curr_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

        entry = ExecutionAuditEntry(
            index=idx,
            timestamp=ts,
            stage=stage,
            incident_id=incident_id,
            status=status,
            action_type=action_type,
            target_resource_id=target_resource_id,
            pre_state_hash=pre_state_hash,
            post_state_hash=post_state_hash,
            metadata=meta,
            previous_hash=prev_hash,
            current_hash=curr_hash,
        )

        self.chain.append(entry)
        return entry

    def verify_integrity(self) -> bool:
        """
        Verify that no record in the execution ledger has been tampered with or deleted.
        """
        if not self.chain:
            return True

        for i, entry in enumerate(self.chain):
            expected_prev = self._genesis_hash if i == 0 else self.chain[i - 1].current_hash
            if entry.previous_hash != expected_prev:
                return False

            payload = {
                "index": entry.index,
                "timestamp": entry.timestamp,
                "stage": entry.stage,
                "incident_id": entry.incident_id,
                "status": entry.status,
                "action_type": entry.action_type,
                "target_resource_id": entry.target_resource_id,
                "pre_state_hash": entry.pre_state_hash,
                "post_state_hash": entry.post_state_hash,
                "metadata": entry.metadata,
                "previous_hash": entry.previous_hash,
            }
            computed_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            if entry.current_hash != computed_hash:
                return False

        return True
