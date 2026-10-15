"""
Controlled Incident Response Workflow for SentinelGuard (Phase 7).
Orchestrates the entire incident response lifecycle:
Incident -> Agent Investigation -> Governor Verification -> Human Approval Gate
-> TOCTOU Pre-Execution Validation -> Simulated Dispatch -> Post-Execution Verification -> Audit Trail.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from sentinelguard.agent.investigator import IncidentInvestigatorAgent
from sentinelguard.agent.schemas import InvestigationAssessment, SecurityIncident
from sentinelguard.core.engine import SentinelGuardGovernor
from sentinelguard.core.schemas import (
    ActionType,
    DecisionType,
    GovernanceDecision,
    RemediationAction,
)
from sentinelguard.execution.approval_gate import HumanApprovalGate
from sentinelguard.execution.audit_trail import ExecutionAuditLedger
from sentinelguard.execution.aws_guardrail import AWSExecutionGuardrail
from sentinelguard.execution.environment import SimulatedCloudEnvironment
from sentinelguard.execution.post_verifier import PostExecutionVerifier
from sentinelguard.execution.schemas import (
    ApprovalStatus,
    ApprovalTicket,
    ExecutionResult,
    PostVerificationResult,
    TOCTOUValidationResult,
    WorkflowExecutionResult,
    WorkflowStatus,
)
from sentinelguard.execution.toctou_guard import TOCTOUGuard


class ControlledIncidentResponseWorkflow:
    """
    State-machine orchestrator coordinating end-to-end incident investigation,
    governance verification, human gates, TOCTOU safety guards, and controlled execution.
    """

    def __init__(
        self,
        environment: SimulatedCloudEnvironment,
        governor: Optional[SentinelGuardGovernor] = None,
        agent: Optional[IncidentInvestigatorAgent] = None,
        approval_gate: Optional[HumanApprovalGate] = None,
        audit_ledger: Optional[ExecutionAuditLedger] = None,
        enforce_tier_0_approval: bool = True,
    ) -> None:
        self.environment = environment
        self.governor = governor or SentinelGuardGovernor(environment.get_state_snapshot())
        self.agent = agent or IncidentInvestigatorAgent()
        self.approval_gate = approval_gate or HumanApprovalGate()
        self.audit_ledger = audit_ledger or ExecutionAuditLedger()
        self.enforce_tier_0_approval = enforce_tier_0_approval
        self._pending_context: Dict[str, Dict[str, Any]] = {}

    def execute_incident_workflow(
        self,
        incident: SecurityIncident,
        execution_mode: str = "SIMULATED",
    ) -> WorkflowExecutionResult:
        """
        Execute an end-to-end incident response workflow with multi-layer verification.
        """
        t0 = time.perf_counter()
        AWSExecutionGuardrail.assert_simulation_safety(execution_mode)

        # -------------------------------------------------------------------
        # Step 1: Capture Pre-Investigation Baseline Fingerprint
        # -------------------------------------------------------------------
        baseline_snapshot = self.environment.get_state_snapshot()
        baseline_fingerprint = self.environment.compute_state_fingerprint()

        # Snapshot tracked resources for TOCTOU comparison
        tracked_snapshots: Dict[str, Dict[str, Any]] = {}
        for r_id in incident.affected_resource_ids:
            r = self.environment.get_resource(r_id)
            if r:
                tracked_snapshots[r_id] = {
                    "status": r.status,
                    "properties": dict(r.properties),
                }

        # -------------------------------------------------------------------
        # Step 2: Agent Investigation & RAG Playbook Retrieval
        # -------------------------------------------------------------------
        assessment: InvestigationAssessment = self.agent.investigate(incident)

        self.audit_ledger.record_stage(
            stage="INVESTIGATION",
            incident_id=incident.incident_id,
            status="COMPLETED",
            metadata={
                "summary": assessment.summary,
                "prompt_injection": assessment.prompt_injection_detected,
                "references": assessment.retrieved_references,
            },
        )

        # -------------------------------------------------------------------
        # Step 3: Handle Prompt Injection Detection (Fail-Closed)
        # -------------------------------------------------------------------
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
            audit_entry = self.audit_ledger.record_stage(
                stage="GOVERNOR_VERIFICATION",
                incident_id=incident.incident_id,
                status="BLOCKED",
                action_type=synth_action.action_type.value,
                target_resource_id=synth_action.target_resource_id,
                metadata={"reason": governor_decision.reason},
            )
            return WorkflowExecutionResult(
                incident_id=incident.incident_id,
                final_status=WorkflowStatus.BLOCKED,
                governor_decision=governor_decision,
                audit_hash=audit_entry.current_hash,
                execution_time_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # -------------------------------------------------------------------
        # Step 4: Handle Missing or Empty Recommendation (Fail-Closed)
        # -------------------------------------------------------------------
        if assessment.recommended_action is None:
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
                reason="Agent could not verify a safe automated action. Escalating to human analyst.",
                blast_radius=[],
            )
            ticket = self.approval_gate.create_ticket(incident.incident_id, governor_decision)
            audit_entry = self.audit_ledger.record_stage(
                stage="APPROVAL_GATE",
                incident_id=incident.incident_id,
                status="APPROVAL_REQUIRED",
                metadata={"ticket_id": ticket.ticket_id, "reason": governor_decision.reason},
            )
            return WorkflowExecutionResult(
                incident_id=incident.incident_id,
                final_status=WorkflowStatus.APPROVAL_REQUIRED,
                governor_decision=governor_decision,
                approval_ticket=ticket,
                audit_hash=audit_entry.current_hash,
                execution_time_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # -------------------------------------------------------------------
        # Step 5: Governor Verification over Current State Snapshot
        # -------------------------------------------------------------------
        # Ensure governor evaluates against pre-investigation baseline snapshot
        self.governor.odg = baseline_snapshot
        remediation_action = assessment.recommended_action.to_remediation_action()
        governor_decision = self.governor.evaluate_action(remediation_action)

        self.audit_ledger.record_stage(
            stage="GOVERNOR_VERIFICATION",
            incident_id=incident.incident_id,
            status=governor_decision.decision.value,
            action_type=remediation_action.action_type.value,
            target_resource_id=remediation_action.target_resource_id,
            metadata={
                "reason": governor_decision.reason,
                "executed_action": governor_decision.executed_action.action_type.value if governor_decision.executed_action else None,
            },
        )

        if governor_decision.decision == DecisionType.BLOCK:
            audit_entry = self.audit_ledger.record_stage(
                stage="DISPATCH",
                incident_id=incident.incident_id,
                status="BLOCKED",
                metadata={"reason": governor_decision.reason},
            )
            return WorkflowExecutionResult(
                incident_id=incident.incident_id,
                final_status=WorkflowStatus.BLOCKED,
                governor_decision=governor_decision,
                audit_hash=audit_entry.current_hash,
                execution_time_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # -------------------------------------------------------------------
        # Step 6: Human Approval Gate Check
        # -------------------------------------------------------------------
        if self.approval_gate.requires_approval(
            governor_decision, self.environment, self.enforce_tier_0_approval
        ):
            ticket = self.approval_gate.create_ticket(incident.incident_id, governor_decision)
            self._pending_context[ticket.ticket_id] = {
                "incident": incident,
                "baseline_snapshot": baseline_snapshot,
                "baseline_fingerprint": baseline_fingerprint,
                "tracked_snapshots": tracked_snapshots,
                "governor_decision": governor_decision,
                "t0": t0,
            }

            if ticket.status == ApprovalStatus.PENDING:
                audit_entry = self.audit_ledger.record_stage(
                    stage="APPROVAL_GATE",
                    incident_id=incident.incident_id,
                    status="PENDING_HUMAN_SIGN_OFF",
                    metadata={"ticket_id": ticket.ticket_id},
                )
                return WorkflowExecutionResult(
                    incident_id=incident.incident_id,
                    final_status=WorkflowStatus.APPROVAL_REQUIRED,
                    governor_decision=governor_decision,
                    approval_ticket=ticket,
                    audit_hash=audit_entry.current_hash,
                    execution_time_ms=(time.perf_counter() - t0) * 1000.0,
                )

        # -------------------------------------------------------------------
        # Step 7: Proceed to Execution Pipeline
        # -------------------------------------------------------------------
        return self._dispatch_and_verify(
            incident=incident,
            governor_decision=governor_decision,
            baseline_snapshot=baseline_snapshot,
            baseline_fingerprint=baseline_fingerprint,
            tracked_snapshots=tracked_snapshots,
            t0=t0,
            approval_ticket=None,
        )

    def resume_workflow_with_approval(
        self,
        ticket_id: str,
        approver_id: str,
        approved: bool,
        rationale: str,
    ) -> WorkflowExecutionResult:
        """
        Resume a paused workflow after a human operator resolves the approval ticket.
        """
        context = self._pending_context.get(ticket_id)
        if not context:
            raise KeyError(f"No pending workflow context found for ticket '{ticket_id}'.")

        ticket = self.approval_gate.resolve_ticket(
            ticket_id=ticket_id,
            approver_id=approver_id,
            approved=approved,
            rationale=rationale,
        )

        self.audit_ledger.record_stage(
            stage="APPROVAL_GATE",
            incident_id=context["incident"].incident_id,
            status="APPROVED" if approved else "REJECTED",
            metadata={
                "ticket_id": ticket_id,
                "approver_id": approver_id,
                "rationale": rationale,
            },
        )

        if not approved:
            audit_entry = self.audit_ledger.record_stage(
                stage="DISPATCH",
                incident_id=context["incident"].incident_id,
                status="HALTED_BY_OPERATOR",
            )
            return WorkflowExecutionResult(
                incident_id=context["incident"].incident_id,
                final_status=WorkflowStatus.REJECTED,
                governor_decision=context["governor_decision"],
                approval_ticket=ticket,
                audit_hash=audit_entry.current_hash,
                execution_time_ms=(time.perf_counter() - context["t0"]) * 1000.0,
            )

        # If approved, proceed with execution
        return self._dispatch_and_verify(
            incident=context["incident"],
            governor_decision=context["governor_decision"],
            baseline_snapshot=context["baseline_snapshot"],
            baseline_fingerprint=context["baseline_fingerprint"],
            tracked_snapshots=context["tracked_snapshots"],
            t0=context["t0"],
            approval_ticket=ticket,
        )

    def _dispatch_and_verify(
        self,
        incident: SecurityIncident,
        governor_decision: GovernanceDecision,
        baseline_snapshot: Optional[Any],
        baseline_fingerprint: str,
        tracked_snapshots: Dict[str, Dict[str, Any]],
        t0: float,
        approval_ticket: Optional[ApprovalTicket],
    ) -> WorkflowExecutionResult:
        """
        Internal execution dispatcher enforcing TOCTOU pre-validation,
        simulated cloud mutation, and post-execution invariant verification.
        """
        action_to_execute = governor_decision.executed_action
        if not action_to_execute:
            audit_entry = self.audit_ledger.record_stage(
                stage="DISPATCH",
                incident_id=incident.incident_id,
                status="NO_ACTION_TO_EXECUTE",
            )
            return WorkflowExecutionResult(
                incident_id=incident.incident_id,
                final_status=WorkflowStatus.BLOCKED,
                governor_decision=governor_decision,
                approval_ticket=approval_ticket,
                audit_hash=audit_entry.current_hash,
                execution_time_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # -------------------------------------------------------------------
        # Step 8: Pre-Execution TOCTOU Revalidation
        # -------------------------------------------------------------------
        toctou_result: TOCTOUValidationResult = TOCTOUGuard.validate_pre_execution(
            environment=self.environment,
            baseline_fingerprint=baseline_fingerprint,
            decision=governor_decision,
            tracked_resources_snapshot=tracked_snapshots,
            baseline_graph=baseline_snapshot,
        )

        self.audit_ledger.record_stage(
            stage="TOCTOU_CHECK",
            incident_id=incident.incident_id,
            status="PASSED" if toctou_result.valid else "FAILED_DRIFT_DETECTED",
            pre_state_hash=toctou_result.baseline_hash,
            post_state_hash=toctou_result.current_hash,
            metadata={"drifted_resources": toctou_result.drifted_resources, "reason": toctou_result.reason},
        )

        if not toctou_result.valid:
            audit_entry = self.audit_ledger.record_stage(
                stage="DISPATCH",
                incident_id=incident.incident_id,
                status="ABORTED_STATE_DRIFT",
                metadata={"reason": toctou_result.reason},
            )
            return WorkflowExecutionResult(
                incident_id=incident.incident_id,
                final_status=WorkflowStatus.ABORTED_STATE_DRIFT,
                governor_decision=governor_decision,
                approval_ticket=approval_ticket,
                toctou_result=toctou_result,
                audit_hash=audit_entry.current_hash,
                execution_time_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # -------------------------------------------------------------------
        # Step 9: Controlled Execution Dispatch
        # -------------------------------------------------------------------
        exec_result: ExecutionResult = self.environment.execute_action(action_to_execute)

        self.audit_ledger.record_stage(
            stage="DISPATCH",
            incident_id=incident.incident_id,
            status="SUCCESS" if exec_result.success else "EXECUTION_FAILED",
            action_type=action_to_execute.action_type.value,
            target_resource_id=action_to_execute.target_resource_id,
            pre_state_hash=exec_result.pre_state_hash,
            post_state_hash=exec_result.post_state_hash,
            metadata={"message": exec_result.message, "error_code": exec_result.error_code},
        )

        if not exec_result.success:
            audit_entry = self.audit_ledger.record_stage(
                stage="POST_VERIFICATION",
                incident_id=incident.incident_id,
                status="SKIPPED_DUE_TO_DISPATCH_FAILURE",
            )
            return WorkflowExecutionResult(
                incident_id=incident.incident_id,
                final_status=WorkflowStatus.EXECUTION_FAILED,
                governor_decision=governor_decision,
                approval_ticket=approval_ticket,
                toctou_result=toctou_result,
                execution_result=exec_result,
                audit_hash=audit_entry.current_hash,
                execution_time_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # -------------------------------------------------------------------
        # Step 10: Post-Execution Invariant Verification
        # -------------------------------------------------------------------
        post_ver: PostVerificationResult = PostExecutionVerifier.verify(
            environment=self.environment,
            action=action_to_execute,
        )

        audit_entry = self.audit_ledger.record_stage(
            stage="POST_VERIFICATION",
            incident_id=incident.incident_id,
            status="PASSED" if post_ver.verified else "FAILED",
            metadata={
                "message": post_ver.message,
                "invariants_passed": post_ver.invariants_passed,
                "target_state_valid": post_ver.target_state_valid,
                "violations": post_ver.live_invariant_violations,
            },
        )

        final_status = (
            WorkflowStatus.SUCCESS if post_ver.verified else WorkflowStatus.POST_VERIFICATION_FAILED
        )

        return WorkflowExecutionResult(
            incident_id=incident.incident_id,
            final_status=final_status,
            governor_decision=governor_decision,
            approval_ticket=approval_ticket,
            toctou_result=toctou_result,
            execution_result=exec_result,
            post_verification=post_ver,
            audit_hash=audit_entry.current_hash,
            execution_time_ms=(time.perf_counter() - t0) * 1000.0,
        )
