"""
SentinelGuard Governor Engine.
Implements the 10-step verified remediation lifecycle:
ALLOW, BLOCK, MODIFY (verified mitigation), or REQUEST_APPROVAL.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional
from sentinelguard.core.audit import AuditLedger
from sentinelguard.core.graph import OperationalDependencyGraph
from sentinelguard.core.invariants import InvariantEngine
from sentinelguard.core.mitigations import MitigationGenerator
from sentinelguard.core.schemas import (
    ActionType,
    DecisionType,
    GovernanceDecision,
    InvariantCheckResult,
    RemediationAction,
)
from sentinelguard.core.simulator import SpeculativeSimulator


class SentinelGuardGovernor:
    """
    State-Aware Security Governor for AI Agent Remediation Actions.
    Evaluates actions against live cloud topology and operational invariants before dispatch.
    """

    def __init__(
        self,
        odg: OperationalDependencyGraph,
        audit_ledger: Optional[AuditLedger] = None,
    ) -> None:
        self.odg = odg
        self.audit_ledger = audit_ledger or AuditLedger()

    def evaluate_action(
        self,
        action: RemediationAction,
        authorized_actions: Optional[List[ActionType]] = None,
    ) -> GovernanceDecision:
        """
        Execute the 10-step verification lifecycle for a proposed remediation action.
        """
        blast_radius = self.odg.compute_blast_radius(action.target_resource_id)
        target_res = self.odg.get_resource(action.target_resource_id)

        # -------------------------------------------------------------------
        # Step 1: Schema & Target Existence Validation
        # -------------------------------------------------------------------
        if not target_res:
            decision = GovernanceDecision(
                decision=DecisionType.BLOCK,
                original_action=action,
                executed_action=None,
                reason=f"Target resource '{action.target_resource_id}' does not exist in environment topology.",
                blast_radius=[],
            )
            self.audit_ledger.record_decision(decision)
            return decision

        # -------------------------------------------------------------------
        # Step 2: Policy & Authorization Check
        # -------------------------------------------------------------------
        allowed_types = authorized_actions or [
            ActionType.ISOLATE_INSTANCE,
            ActionType.REVOKE_ACCESS_KEY,
            ActionType.REMOVE_PERMISSION,
        ]
        if action.action_type not in allowed_types:
            decision = GovernanceDecision(
                decision=DecisionType.BLOCK,
                original_action=action,
                executed_action=None,
                reason=(
                    f"Action type '{action.action_type.value}' is unauthorized for agent role '{action.actor}'."
                ),
                blast_radius=blast_radius,
            )
            self.audit_ledger.record_decision(decision)
            return decision

        # -------------------------------------------------------------------
        # Step 3: Speculative Counterfactual Simulation
        # S' = f(S0, a)
        # -------------------------------------------------------------------
        projected_state = SpeculativeSimulator.simulate(self.odg, action)

        # -------------------------------------------------------------------
        # Step 4: Check Operational Invariants on S'
        # -------------------------------------------------------------------
        target_account = target_res.account_id
        check_result: InvariantCheckResult = InvariantEngine.evaluate_all(
            projected_state, target_account_id=target_account
        )

        inv_summary = {
            "I_Admin": not any(v.invariant_id == "I_Admin" for v in check_result.violations),
            "I_Avail": not any(v.invariant_id == "I_Avail" for v in check_result.violations),
            "I_Telem": not any(v.invariant_id == "I_Telem" for v in check_result.violations),
        }

        # If all invariants pass -> ALLOW
        if check_result.passed:
            decision = GovernanceDecision(
                decision=DecisionType.ALLOW,
                original_action=action,
                executed_action=action,
                reason="Action verified safe. All operational invariants satisfied in projected cloud state.",
                invariant_results=inv_summary,
                violations=[],
                blast_radius=blast_radius,
            )
            self.audit_ledger.record_decision(decision)
            return decision

        # -------------------------------------------------------------------
        # Steps 5-7: Bounded Mitigation Search & Verification
        # -------------------------------------------------------------------
        alternatives = MitigationGenerator.generate_alternatives(
            self.odg, action, check_result.violations
        )

        evaluated_alts = []
        verified_alt: Optional[RemediationAction] = None

        for alt in alternatives:
            alt_projected = SpeculativeSimulator.simulate(self.odg, alt)
            alt_check = InvariantEngine.evaluate_all(alt_projected, target_account_id=target_account)
            evaluated_alts.append({
                "action_type": alt.action_type.value,
                "passed": alt_check.passed,
                "violations_count": len(alt_check.violations),
            })

            if alt_check.passed and verified_alt is None:
                verified_alt = alt

        # If a verified mitigation exists -> MODIFY
        if verified_alt is not None:
            decision = GovernanceDecision(
                decision=DecisionType.MODIFY,
                original_action=action,
                executed_action=verified_alt,
                reason=(
                    f"Original action failed operational invariants ({', '.join(v.invariant_id.value for v in check_result.violations)}). "
                    f"Selected verified mitigation '{verified_alt.action_type.value}' preserving service stability."
                ),
                invariant_results=inv_summary,
                violations=check_result.violations,
                alternatives_evaluated=evaluated_alts,
                blast_radius=blast_radius,
            )
            self.audit_ledger.record_decision(decision)
            return decision

        # -------------------------------------------------------------------
        # No Safe Automated Alternative -> REQUEST_APPROVAL or BLOCK
        # -------------------------------------------------------------------
        has_critical = any(v.severity == "CRITICAL" for v in check_result.violations)
        if has_critical:
            # Operational lockout or service outage risk -> Escalate to human gate
            decision = GovernanceDecision(
                decision=DecisionType.REQUEST_APPROVAL,
                original_action=action,
                executed_action=None,
                reason=(
                    f"Action would trigger catastrophic operational failure: "
                    f"{'; '.join(v.message for v in check_result.violations)}. "
                    f"No automated mitigation is safely verifiable. Escalating to human approval gate."
                ),
                invariant_results=inv_summary,
                violations=check_result.violations,
                alternatives_evaluated=evaluated_alts,
                blast_radius=blast_radius,
            )
        else:
            decision = GovernanceDecision(
                decision=DecisionType.BLOCK,
                original_action=action,
                executed_action=None,
                reason=(
                    f"Action violates policy constraints: {'; '.join(v.message for v in check_result.violations)}."
                ),
                invariant_results=inv_summary,
                violations=check_result.violations,
                alternatives_evaluated=evaluated_alts,
                blast_radius=blast_radius,
            )

        self.audit_ledger.record_decision(decision)
        return decision
