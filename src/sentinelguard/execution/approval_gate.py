"""
Human Approval Gate for SentinelGuard (Phase 7).
Enforces human-in-the-loop signoff for high-impact actions and operational traps
where automated mitigations are insufficient or dangerous.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional

from sentinelguard.core.schemas import CriticalityTier, DecisionType, GovernanceDecision
from sentinelguard.execution.environment import SimulatedCloudEnvironment
from sentinelguard.execution.schemas import ApprovalStatus, ApprovalTicket


class HumanApprovalGate:
    """
    Manages human approval tickets for incident response actions.
    Ensures high-impact and ambiguous actions are paused until explicit operator sign-off.
    """

    def __init__(self, auto_approve_policy: bool = False) -> None:
        self.tickets: Dict[str, ApprovalTicket] = {}
        self.auto_approve_policy = auto_approve_policy
        self._ticket_counter = 0

    def requires_approval(
        self,
        decision: GovernanceDecision,
        environment: Optional[SimulatedCloudEnvironment] = None,
        enforce_tier_0_policy: bool = True,
    ) -> bool:
        """
        Determine if an action mandates human approval before execution.
        """
        # 1. Governor explicitly demanded human approval
        if decision.decision == DecisionType.REQUEST_APPROVAL:
            return True

        # 2. Blocked or Allow without action does not require approval
        if decision.decision == DecisionType.BLOCK or not decision.executed_action:
            return False

        # 3. Check if target resource is Tier-0 mission-critical
        if enforce_tier_0_policy and environment:
            target = environment.get_resource(decision.executed_action.target_resource_id)
            if target and target.criticality == CriticalityTier.TIER_0:
                # If an action directly affects a Tier-0 asset, require explicit human confirmation
                # unless it's a non-destructive scoped mitigation
                if decision.decision == DecisionType.ALLOW and decision.executed_action.action_type.value in {
                    "revoke_access_key",
                    "isolate_instance",
                }:
                    return True

        return False

    def create_ticket(self, incident_id: str, decision: GovernanceDecision) -> ApprovalTicket:
        """
        Create a new pending human approval ticket.
        """
        self._ticket_counter += 1
        ticket_id = f"TICKET-{int(time.time())}-{self._ticket_counter:03d}"

        ticket = ApprovalTicket(
            ticket_id=ticket_id,
            incident_id=incident_id,
            decision=decision,
            status=ApprovalStatus.PENDING,
            created_at=time.time(),
        )

        if self.auto_approve_policy:
            ticket.status = ApprovalStatus.APPROVED
            ticket.approver_id = "auto_approver_policy"
            ticket.rationale = "Automatically approved by test harness policy."
            ticket.resolved_at = time.time()

        self.tickets[ticket_id] = ticket
        return ticket

    def get_ticket(self, ticket_id: str) -> Optional[ApprovalTicket]:
        return self.tickets.get(ticket_id)

    def resolve_ticket(
        self,
        ticket_id: str,
        approver_id: str,
        approved: bool,
        rationale: str,
    ) -> ApprovalTicket:
        """
        Submit a human operator's decision on a pending ticket.
        """
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            raise KeyError(f"Approval ticket '{ticket_id}' not found.")

        if ticket.status != ApprovalStatus.PENDING:
            raise ValueError(f"Ticket '{ticket_id}' has already been resolved with status '{ticket.status.value}'.")

        ticket.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        ticket.approver_id = approver_id
        ticket.rationale = rationale
        ticket.resolved_at = time.time()
        return ticket

    def list_pending_tickets(self) -> List[ApprovalTicket]:
        return [t for t in self.tickets.values() if t.status == ApprovalStatus.PENDING]
