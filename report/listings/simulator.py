"""
Pure-Python Counterfactual Simulator.
Projects speculative state transitions S' = f(S_0, a) without touching live cloud resources.
"""

from __future__ import annotations

from typing import Tuple
from sentinelguard.core.graph import OperationalDependencyGraph
from sentinelguard.core.schemas import (
    ActionType,
    CloudResource,
    RemediationAction,
    ResourceType,
)


class SpeculativeSimulator:
    """
    Applies candidate remediation actions to an isolated clone of the
    Operational Dependency Graph, producing a projected future state S'.
    """

    @staticmethod
    def simulate(
        initial_state: OperationalDependencyGraph,
        action: RemediationAction,
    ) -> OperationalDependencyGraph:
        """
        Produce projected world state S' = f(S0, a).
        Does NOT mutate initial_state.
        """
        # Deep clone to isolate speculative mutations
        speculative_state = initial_state.clone()
        target_res = speculative_state.get_resource(action.target_resource_id)

        if not target_res:
            # Target does not exist in graph; return unmodified clone
            return speculative_state

        if action.action_type == ActionType.ISOLATE_INSTANCE:
            SpeculativeSimulator._apply_isolate_instance(
                speculative_state, target_res, action
            )
        elif action.action_type == ActionType.REVOKE_ACCESS_KEY:
            SpeculativeSimulator._apply_revoke_access_key(
                speculative_state, target_res, action
            )
        elif action.action_type == ActionType.REMOVE_PERMISSION:
            SpeculativeSimulator._apply_remove_permission(
                speculative_state, target_res, action
            )
        elif action.action_type == ActionType.ATTACH_SCOPED_EGRESS_FILTER:
            SpeculativeSimulator._apply_scoped_egress_filter(
                speculative_state, target_res, action
            )
        elif action.action_type == ActionType.DEREGISTER_AND_DRAIN:
            SpeculativeSimulator._apply_deregister_and_drain(
                speculative_state, target_res, action
            )
        elif action.action_type == ActionType.SCOPE_PERMISSION_TO_RESOURCE:
            SpeculativeSimulator._apply_scope_permission(
                speculative_state, target_res, action
            )

        return speculative_state

    # -----------------------------------------------------------------------
    # Action Handlers
    # -----------------------------------------------------------------------

    @staticmethod
    def _apply_isolate_instance(
        state: OperationalDependencyGraph,
        instance: CloudResource,
        action: RemediationAction,
    ) -> None:
        """
        Simulate isolating an EC2 instance:
        - Changes status to 'isolated'.
        - Standard quarantine cuts all ingress/egress, severing health-checks.
        """
        instance.status = "isolated"
        instance.properties["is_quarantined"] = True

        # Check if isolation breaks health check ingress for attached target groups
        preserves_health_checks = action.parameters.get("preserve_health_checks", False)
        if not preserves_health_checks:
            instance.properties["health_check_accessible"] = False

        # If CloudWatch host agent runs on this instance, isolation cuts its network egress
        for pred in state.g.predecessors(instance.id):
            agent = state.get_resource(pred)
            if agent and agent.resource_type == ResourceType.CLOUDWATCH_AGENT:
                agent.properties["cloudwatch_endpoint_accessible"] = False

    @staticmethod
    def _apply_revoke_access_key(
        state: OperationalDependencyGraph,
        key: CloudResource,
        action: RemediationAction,
    ) -> None:
        """
        Simulate revoking an IAM access key:
        - Marks key inactive/revoked.
        """
        key.status = "revoked"
        key.properties["is_active"] = False

    @staticmethod
    def _apply_remove_permission(
        state: OperationalDependencyGraph,
        principal_or_policy: CloudResource,
        action: RemediationAction,
    ) -> None:
        """
        Simulate removing an IAM permission policy:
        - May impact admin capability or telemetry delivery roles.
        """
        policy_id = action.parameters.get("policy_id")
        removed_action = action.parameters.get("permission_name")

        if policy_id:
            state.remove_dependency(principal_or_policy.id, policy_id)

        # Check if telemetry delivery is impacted
        if principal_or_policy.properties.get("is_telemetry_role", False):
            if removed_action in {"s3:PutObject", "logs:PutLogEvents", "*"}:
                principal_or_policy.properties["has_delivery_permission"] = False

        if principal_or_policy.resource_type == ResourceType.S3_BUCKET:
            if action.parameters.get("block_service_delivery"):
                principal_or_policy.properties["allows_cloudtrail_delivery"] = False

        if principal_or_policy.resource_type == ResourceType.KMS_KEY:
            if action.parameters.get("disable_key"):
                principal_or_policy.status = "disabled"
                principal_or_policy.properties["allows_cloudtrail_kms"] = False

    @staticmethod
    def _apply_scoped_egress_filter(
        state: OperationalDependencyGraph,
        instance: CloudResource,
        action: RemediationAction,
    ) -> None:
        """
        Simulate attaching a scoped egress filter (safe mitigation):
        - Instance remains active and healthy.
        - Attacker external C2 is blocked.
        - VPC internal health checks and CloudWatch telemetry remain intact.
        """
        instance.status = "active"
        instance.properties["is_egress_filtered"] = True
        instance.properties["threat_contained"] = True
        instance.properties["health_check_accessible"] = True

    @staticmethod
    def _apply_deregister_and_drain(
        state: OperationalDependencyGraph,
        instance: CloudResource,
        action: RemediationAction,
    ) -> None:
        """
        Simulate deregistering instance from target group with connection draining.
        """
        instance.status = "draining"
        instance.properties["is_draining"] = True

    @staticmethod
    def _apply_scope_permission(
        state: OperationalDependencyGraph,
        resource: CloudResource,
        action: RemediationAction,
    ) -> None:
        """
        Simulate scoping a wide permission down to a least-privilege resource boundary.
        """
        resource.properties["is_scoped_down"] = True
        resource.properties["threat_contained"] = True
