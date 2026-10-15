"""
Incident Response Orchestration Pipeline for SentinelGuard.
Connects:
Incident -> RAG Retrieval -> Investigation Agent -> Action Validation -> Existing Governor -> Audit Record.
Enforces fail-closed behavior with zero direct cloud execution.
"""

from __future__ import annotations

import time
from typing import Optional

from sentinelguard.agent.investigator import IncidentInvestigatorAgent
from sentinelguard.agent.schemas import (
    InvestigationAssessment,
    InvestigationReport,
    SecurityIncident,
)
from sentinelguard.core.audit import AuditLedger
from sentinelguard.core.engine import SentinelGuardGovernor
from sentinelguard.core.schemas import (
    ActionType,
    DecisionType,
    GovernanceDecision,
    RemediationAction,
)


class IncidentResponsePipeline:
    """
    End-to-end incident response orchestration pipeline.
    Coordinates AI investigation agent with the deterministic SentinelGuard Governor.
    """

    def __init__(
        self,
        governor: SentinelGuardGovernor,
        agent: Optional[IncidentInvestigatorAgent] = None,
    ) -> None:
        self.governor = governor
        self.agent = agent or IncidentInvestigatorAgent()
        self.audit_ledger = governor.audit_ledger

    def process_incident(self, incident: SecurityIncident) -> InvestigationReport:
        """
        Process a security incident end-to-end:
        1. Agent investigates incident using RAG and LLM.
        2. Validated proposal is submitted to SentinelGuard Governor.
        3. Governor verifies operational invariants and returns final decision.
        4. Complete decision and blast radius are recorded in tamper-evident audit ledger.
        """
        t0 = time.perf_counter()

        # Step 1: Agent Investigation & RAG retrieval
        assessment: InvestigationAssessment = self.agent.investigate(incident)

        governor_decision: Optional[GovernanceDecision] = None

        # Step 2: Handle Prompt Injection Detection (Fail-Closed)
        if assessment.prompt_injection_detected:
            synth_action = RemediationAction(
                action_type=ActionType.REMOVE_PERMISSION,
                target_resource_id=incident.affected_resource_ids[0] if incident.affected_resource_ids else "unknown",
                rationale="Adversarial injection attempt blocked.",
                actor="adversary_blocked",
            )
            governor_decision = GovernanceDecision(
                decision=DecisionType.BLOCK,
                original_action=synth_action,
                executed_action=None,
                reason="Adversarial prompt injection attempt detected and neutralized. Remediation halted.",
                blast_radius=[],
            )
            self.audit_ledger.record_decision(governor_decision)

        # Step 3: Handle Missing or Empty Recommendation (Fail-Closed)
        elif assessment.recommended_action is None:
            synth_action = RemediationAction(
                action_type=ActionType.ISOLATE_INSTANCE,
                target_resource_id=incident.affected_resource_ids[0] if incident.affected_resource_ids else "unknown",
                rationale="No automated action proposed by agent.",
                actor="ai_investigator_agent",
            )
            governor_decision = GovernanceDecision(
                decision=DecisionType.REQUEST_APPROVAL,
                original_action=synth_action,
                executed_action=None,
                reason=(
                    f"Agent could not verify a safe automated action: "
                    f"{'; '.join(assessment.uncertainty_or_missing_evidence or ['Insufficient telemetry'])}. "
                    f"Escalating to human analyst."
                ),
                blast_radius=[],
            )
            self.audit_ledger.record_decision(governor_decision)

        # Step 4: Submit Validated Proposal to Governor
        else:
            remediation_action = assessment.recommended_action.to_remediation_action()
            governor_decision = self.governor.evaluate_action(remediation_action)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return InvestigationReport(
            incident_id=incident.incident_id,
            assessment=assessment,
            governor_decision=governor_decision,
            audit_hash=governor_decision.audit_hash if governor_decision else None,
            execution_time_ms=elapsed_ms,
        )
