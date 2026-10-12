"""
Core Operational Invariant Checks for SentinelGuard.
Evaluates:
1. I_Admin: Administrative Recovery Invariant
2. I_Avail: Service Availability Invariant
3. I_Telem: Security Telemetry Continuity Invariant
"""

from __future__ import annotations

from typing import List, Tuple
from sentinelguard.core.graph import OperationalDependencyGraph
from sentinelguard.core.schemas import (
    InvariantCheckResult,
    InvariantID,
    InvariantViolation,
    ResourceType,
)


class InvariantEngine:
    """
    Evaluates system-wide operational invariants against a projected cloud state S'.
    """

    @classmethod
    def evaluate_all(
        cls, state: OperationalDependencyGraph, target_account_id: str = "123456789012"
    ) -> InvariantCheckResult:
        """
        Run all three foundational invariants against state S'.
        Returns aggregate InvariantCheckResult with violation details.
        """
        violations: List[InvariantViolation] = []

        # 1. Administrative Recovery
        admin_violations = cls.check_administrative_recovery(state, target_account_id)
        violations.extend(admin_violations)

        # 2. Service Availability
        avail_violations = cls.check_service_availability(state)
        violations.extend(avail_violations)

        # 3. Security Telemetry Continuity
        telem_violations = cls.check_telemetry_continuity(state)
        violations.extend(telem_violations)

        passed = len(violations) == 0
        return InvariantCheckResult(passed=passed, violations=violations)

    # -----------------------------------------------------------------------
    # Invariant 1: Administrative Recovery (I_Admin)
    # -----------------------------------------------------------------------

    @classmethod
    def check_administrative_recovery(
        cls, state: OperationalDependencyGraph, account_id: str
    ) -> List[InvariantViolation]:
        """
        Verifies that at least one independent, authorized recovery path remains
        operational and reachable for the specified account.
        """
        violations: List[InvariantViolation] = []
        recovery_paths = state.get_active_admin_paths(account_id=account_id)

        if len(recovery_paths) == 0:
            violations.append(
                InvariantViolation(
                    invariant_id=InvariantID.ADMINISTRATIVE_RECOVERY,
                    message=(
                        f"Zero reachable administrative recovery paths remain for account '{account_id}'. "
                        "Action would cause complete administrative lockout."
                    ),
                    impacted_resource_ids=[account_id],
                    severity="CRITICAL",
                )
            )

        return violations

    # -----------------------------------------------------------------------
    # Invariant 2: Service Availability (I_Avail)
    # -----------------------------------------------------------------------

    @classmethod
    def check_service_availability(
        cls, state: OperationalDependencyGraph
    ) -> List[InvariantViolation]:
        """
        Verifies that required healthy capacity and health-check connectivity
        remain above configured minimums for all Tier-0 / Tier-1 target groups.
        """
        violations: List[InvariantViolation] = []
        target_groups = state.get_resources_by_type(ResourceType.TARGET_GROUP)

        for tg in target_groups:
            health = state.get_target_group_health(tg.id)
            min_healthy = health["min_healthy"]
            healthy_count = health["healthy_count"]

            # Quorum check
            if healthy_count < min_healthy:
                violations.append(
                    InvariantViolation(
                        invariant_id=InvariantID.SERVICE_AVAILABILITY,
                        message=(
                            f"Target group '{tg.name}' ({tg.id}) healthy replica count dropped to {healthy_count}, "
                            f"below minimum requirement of {min_healthy}. Quorum breached."
                        ),
                        impacted_resource_ids=[tg.id] + health.get("healthy_instances", []),
                        severity="CRITICAL",
                    )
                )

            # Health-check network reachability check
            if not health["health_check_open"]:
                violations.append(
                    InvariantViolation(
                        invariant_id=InvariantID.SERVICE_AVAILABILITY,
                        message=(
                            f"Target group '{tg.name}' ({tg.id}) health-check port is blocked or unreachable."
                        ),
                        impacted_resource_ids=[tg.id],
                        severity="HIGH",
                    )
                )

        return violations

    # -----------------------------------------------------------------------
    # Invariant 3: Security Telemetry Continuity (I_Telem)
    # -----------------------------------------------------------------------

    @classmethod
    def check_telemetry_continuity(
        cls, state: OperationalDependencyGraph
    ) -> List[InvariantViolation]:
        """
        Resource-specific verification for CloudTrail delivery, VPC Flow Logs,
        and CloudWatch host agents.
        """
        violations: List[InvariantViolation] = []
        telem_status = state.check_telemetry_health()

        # CloudTrail checks
        ct = telem_status.get("cloudtrail", {})
        if not ct.get("healthy", True):
            for trail in ct.get("trails", []):
                if not trail["healthy"]:
                    violations.append(
                        InvariantViolation(
                            invariant_id=InvariantID.TELEMETRY_CONTINUITY,
                            message=f"CloudTrail '{trail['id']}' telemetry severed: {trail['reason']}.",
                            impacted_resource_ids=[trail["id"]],
                            severity="CRITICAL",
                        )
                    )

        # VPC Flow Logs checks
        vfl = telem_status.get("vpc_flow_logs", {})
        if not vfl.get("healthy", True):
            for flow in vfl.get("logs", []):
                if not flow["healthy"]:
                    violations.append(
                        InvariantViolation(
                            invariant_id=InvariantID.TELEMETRY_CONTINUITY,
                            message=f"VPC Flow Log '{flow['id']}' disabled or delivery interrupted: {flow['reason']}.",
                            impacted_resource_ids=[flow["id"]],
                            severity="HIGH",
                        )
                    )

        # CloudWatch Host Agents checks
        cwa = telem_status.get("cloudwatch_agents", {})
        if not cwa.get("healthy", True):
            for agent in cwa.get("agents", []):
                if not agent["healthy"]:
                    violations.append(
                        InvariantViolation(
                            invariant_id=InvariantID.TELEMETRY_CONTINUITY,
                            message=f"CloudWatch Agent '{agent['id']}' cannot deliver audit logs: {agent['reason']}.",
                            impacted_resource_ids=[agent["id"]],
                            severity="HIGH",
                        )
                    )

        return violations
