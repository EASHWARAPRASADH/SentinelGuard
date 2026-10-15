"""
Schemas for SentinelGuard Phase 7: Controlled Cloud Execution & Workflow.
Defines execution results, approval tickets, TOCTOU validation results,
post-execution verifications, and end-to-end workflow states.
"""

from __future__ import annotations

from enum import Enum
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from sentinelguard.core.schemas import GovernanceDecision, RemediationAction


class WorkflowStatus(str, Enum):
    SUCCESS = "SUCCESS"
    BLOCKED = "BLOCKED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    REJECTED = "REJECTED"
    ABORTED_STATE_DRIFT = "ABORTED_STATE_DRIFT"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    POST_VERIFICATION_FAILED = "POST_VERIFICATION_FAILED"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ApprovalTicket(BaseModel):
    ticket_id: str
    incident_id: str
    decision: GovernanceDecision
    status: ApprovalStatus = ApprovalStatus.PENDING
    approver_id: Optional[str] = None
    rationale: Optional[str] = None
    created_at: float = Field(default_factory=time.time)
    resolved_at: Optional[float] = None


class TOCTOUValidationResult(BaseModel):
    valid: bool
    drift_detected: bool
    baseline_hash: str
    current_hash: str
    reason: Optional[str] = None
    drifted_resources: List[str] = Field(default_factory=list)


class ExecutionResult(BaseModel):
    success: bool
    action: RemediationAction
    pre_state_hash: str
    post_state_hash: str
    message: str
    error_code: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)


class PostVerificationResult(BaseModel):
    verified: bool
    target_state_valid: bool
    invariants_passed: bool
    live_invariant_violations: List[str] = Field(default_factory=list)
    message: str


class WorkflowExecutionResult(BaseModel):
    incident_id: str
    final_status: WorkflowStatus
    governor_decision: Optional[GovernanceDecision] = None
    approval_ticket: Optional[ApprovalTicket] = None
    toctou_result: Optional[TOCTOUValidationResult] = None
    execution_result: Optional[ExecutionResult] = None
    post_verification: Optional[PostVerificationResult] = None
    audit_hash: Optional[str] = None
    execution_time_ms: float = 0.0
