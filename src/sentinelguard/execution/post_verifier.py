"""
Post-Execution Verifier for SentinelGuard (Phase 7).
Inspects the actual cloud environment following action execution to confirm:
1. Target resource accurately transitioned into the required security posture.
2. All operational invariants (Admin Recovery, Service Availability, Telemetry Continuity)
   remain satisfied on the live post-action cloud topology.
"""

from __future__ import annotations

from typing import List, Optional

from sentinelguard.core.invariants import InvariantEngine
from sentinelguard.core.schemas import ActionType, RemediationAction
from sentinelguard.execution.environment import SimulatedCloudEnvironment
from sentinelguard.execution.schemas import PostVerificationResult


class PostExecutionVerifier:
    """
    Verifies actual cloud state and operational invariant integrity following execution dispatch.
    """

    @classmethod
    def verify(
        cls,
        environment: SimulatedCloudEnvironment,
        action: RemediationAction,
    ) -> PostVerificationResult:
        """
        Run post-execution checks against the live cloud environment.
        """
        # 1. Target Resource State Validation
        target = environment.get_resource(action.target_resource_id)
        if not target:
            return PostVerificationResult(
                verified=False,
                target_state_valid=False,
                invariants_passed=False,
                live_invariant_violations=["TargetResourceMissing"],
                message=f"Post-verification failed: Target resource '{action.target_resource_id}' does not exist.",
            )

        target_valid = True
        target_reasons: List[str] = []

        if action.action_type == ActionType.ISOLATE_INSTANCE:
            if target.status != "isolated" or not target.properties.get("is_isolated"):
                target_valid = False
                target_reasons.append("Instance status is not isolated.")

        elif action.action_type == ActionType.ATTACH_SCOPED_EGRESS_FILTER:
            if not target.properties.get("scoped_egress_filter_attached"):
                target_valid = False
                target_reasons.append("Scoped egress filter not attached to instance.")

        elif action.action_type == ActionType.DEREGISTER_AND_DRAIN:
            if target.status != "draining":
                target_valid = False
                target_reasons.append("Instance status is not draining.")

        elif action.action_type == ActionType.REVOKE_ACCESS_KEY:
            if target.status != "revoked" or target.properties.get("is_active") is not False:
                target_valid = False
                target_reasons.append("Access key status is not revoked / inactive.")

        elif action.action_type == ActionType.REMOVE_PERMISSION:
            if not target.properties.get("permission_removed"):
                target_valid = False
                target_reasons.append("Target permission not removed.")

        elif action.action_type == ActionType.SCOPE_PERMISSION_TO_RESOURCE:
            if not target.properties.get("scoped_to_resource"):
                target_valid = False
                target_reasons.append("Permission not scoped to resource.")

        # 2. Live Invariant Re-verification on Live Cloud Topology
        check_result = InvariantEngine.evaluate_all(
            environment.live_graph, target_account_id=target.account_id
        )

        invariants_passed = check_result.passed
        violations_messages = [f"{v.invariant_id.value}: {v.message}" for v in check_result.violations]

        verified = target_valid and invariants_passed

        if verified:
            msg = (
                f"Post-execution verification PASSED: Target '{action.target_resource_id}' "
                f"successfully transitioned and all operational invariants are satisfied on live topology."
            )
        else:
            reasons = target_reasons + violations_messages
            msg = f"Post-execution verification FAILED: {'; '.join(reasons)}"

        return PostVerificationResult(
            verified=verified,
            target_state_valid=target_valid,
            invariants_passed=invariants_passed,
            live_invariant_violations=violations_messages,
            message=msg,
        )
