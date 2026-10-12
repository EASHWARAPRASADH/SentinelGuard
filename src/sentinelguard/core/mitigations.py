"""
Bounded Mitigation Lattice for SentinelGuard.
Generates a deterministic, bounded set of candidate alternative actions
when an initial remediation action fails operational invariants.
"""

from __future__ import annotations

from typing import List
from sentinelguard.core.graph import OperationalDependencyGraph
from sentinelguard.core.schemas import (
    ActionType,
    InvariantID,
    InvariantViolation,
    RemediationAction,
    ResourceType,
)


class MitigationGenerator:
    """
    Deterministically generates candidate safer alternative actions from a bounded catalogue.
    Each generated alternative MUST still be verified through counterfactual simulation.
    """

    @classmethod
    def generate_alternatives(
        cls,
        state: OperationalDependencyGraph,
        original_action: RemediationAction,
        violations: List[InvariantViolation],
    ) -> List[RemediationAction]:
        """
        Generate candidate alternative actions tailored to the specific invariant failures.
        """
        alternatives: List[RemediationAction] = []
        violation_ids = {v.invariant_id for v in violations}

        # -------------------------------------------------------------------
        # Case 1: IsolateInstance failed Service Availability (I_Avail)
        # -------------------------------------------------------------------
        if original_action.action_type == ActionType.ISOLATE_INSTANCE:
            if InvariantID.SERVICE_AVAILABILITY in violation_ids:
                # Candidate 1: Attach scoped egress filter (blocks external C2, preserves VPC health-checks)
                alternatives.append(
                    RemediationAction(
                        action_type=ActionType.ATTACH_SCOPED_EGRESS_FILTER,
                        target_resource_id=original_action.target_resource_id,
                        parameters={
                            "preserve_health_checks": True,
                            "block_external_c2": True,
                            "ingress_whitelist": ["vpc_internal", "health_check"],
                        },
                        rationale=(
                            "Mitigation: Attach scoped security group filtering outbound attacker egress "
                            "while preserving internal health-check ingress to maintain service quorum."
                        ),
                        actor="sentinelguard_mitigation_engine",
                    )
                )

        # -------------------------------------------------------------------
        # Case 2: RevokeAccessKey failed Administrative Recovery (I_Admin)
        # -------------------------------------------------------------------
        if original_action.action_type == ActionType.REVOKE_ACCESS_KEY:
            if InvariantID.ADMINISTRATIVE_RECOVERY in violation_ids:
                # Per architectural review:
                # If revoking this key eliminates the only reachable admin path and no independent
                # break-glass role exists, DO NOT apply unverified permissions boundaries.
                # Only offer an alternative if an emergency recovery path can be activated.
                key = state.get_resource(original_action.target_resource_id)
                account_id = key.account_id if key else "123456789012"
                emergency_roles = [
                    res for res in state.get_resources_by_type(ResourceType.IAM_ROLE)
                    if res.account_id == account_id and res.properties.get("is_emergency_recovery", False)
                ]
                if emergency_roles:
                    # An emergency role exists in standby: we can safely revoke key because emergency role is verified
                    alternatives.append(
                        RemediationAction(
                            action_type=ActionType.REVOKE_ACCESS_KEY,
                            target_resource_id=original_action.target_resource_id,
                            parameters={
                                "activate_standby_role": emergency_roles[0].id,
                            },
                            rationale=(
                                f"Mitigation: Revoke compromised key while activating standby "
                                f"emergency recovery role '{emergency_roles[0].id}'."
                            ),
                            actor="sentinelguard_mitigation_engine",
                        )
                    )
                # If no standby emergency role exists, return empty list -> Governor will REQUEST_APPROVAL.

        # -------------------------------------------------------------------
        # Case 3: RemovePermission failed Telemetry Continuity (I_Telem)
        # -------------------------------------------------------------------
        if original_action.action_type == ActionType.REMOVE_PERMISSION:
            if InvariantID.TELEMETRY_CONTINUITY in violation_ids:
                # Candidate: Scope permission to target resource rather than wildcard, preserving telemetry actions
                alternatives.append(
                    RemediationAction(
                        action_type=ActionType.SCOPE_PERMISSION_TO_RESOURCE,
                        target_resource_id=original_action.target_resource_id,
                        parameters={
                            "preserve_actions": ["s3:PutObject", "logs:PutLogEvents"],
                            "strip_wildcards": True,
                        },
                        rationale=(
                            "Mitigation: Scope permission down to specific resource targets, "
                            "preserving necessary telemetry delivery permissions for CloudTrail and CloudWatch."
                        ),
                        actor="sentinelguard_mitigation_engine",
                    )
                )

        return alternatives
