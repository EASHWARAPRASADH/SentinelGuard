"""
Schemas for the SentinelGuard Investigation Agent.
Models incidents, evidence, assessments, proposals, and reports.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from sentinelguard.core.schemas import ActionType, GovernanceDecision, RemediationAction


class SecurityIncident(BaseModel):
    """Structured security incident envelope received by the agent."""
    incident_id: str
    alert_type: str  # e.g., "credential_abuse", "c2_beacon", "privilege_escalation"
    severity: str = "HIGH"  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    timestamp: str
    affected_resource_ids: List[str]
    observed_events: List[Dict[str, Any]] = Field(default_factory=list)
    detection_evidence: Dict[str, Any] = Field(default_factory=dict)
    cloud_metadata: Dict[str, Any] = Field(default_factory=dict)
    untrusted_payload: Optional[str] = None  # Usernames, log payloads with untrusted text


class ActionProposal(BaseModel):
    """A proposed remediation action from the bounded action catalogue."""
    action_type: ActionType
    target_resource_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    rationale: str

    def to_remediation_action(self, actor: str = "ai_investigator_agent") -> RemediationAction:
        """Convert validated proposal to SentinelGuard RemediationAction."""
        return RemediationAction(
            action_type=self.action_type,
            target_resource_id=self.target_resource_id,
            parameters=self.parameters,
            rationale=self.rationale,
            actor=actor,
        )


class InvestigationAssessment(BaseModel):
    """The evidence-grounded assessment produced by the agent."""
    summary: str
    evidence_grounding: List[str] = Field(default_factory=list)
    retrieved_references: List[str] = Field(default_factory=list)
    uncertainty_or_missing_evidence: List[str] = Field(default_factory=list)
    recommended_action: Optional[ActionProposal] = None
    rationale: str
    prompt_injection_detected: bool = False


class InvestigationReport(BaseModel):
    """End-to-end report containing incident, agent assessment, and governor decision."""
    incident_id: str
    assessment: InvestigationAssessment
    governor_decision: Optional[GovernanceDecision] = None
    audit_hash: Optional[str] = None
    execution_time_ms: float = 0.0
