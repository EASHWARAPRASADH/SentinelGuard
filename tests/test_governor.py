"""
Unit and Integration Tests for SentinelGuard Governor Engine.
Demonstrates:
1. Operational Dependency Graph (ODG) construction & querying.
2. Invariant checks (I_Admin, I_Avail, I_Telem).
3. Counterfactual speculative simulation.
4. Three operational-trap scenarios + Safe + Blocked scenarios.
"""

import pytest

from sentinelguard.core.engine import SentinelGuardGovernor
from sentinelguard.core.graph import OperationalDependencyGraph
from sentinelguard.core.schemas import (
    ActionType,
    CloudResource,
    CriticalityTier,
    DecisionType,
    EdgeType,
    InvariantID,
    RemediationAction,
    ResourceType,
)


@pytest.fixture
def base_odg() -> OperationalDependencyGraph:
    """Build a standard cloud topology with compute, IAM, and telemetry."""
    odg = OperationalDependencyGraph()

    # 1. IAM Admin User with Active Access Key
    admin_user = CloudResource(
        id="user-admin-alice",
        resource_type=ResourceType.IAM_USER,
        name="AliceAdmin",
        criticality=CriticalityTier.TIER_0,
        status="active",
        properties={"is_admin": True, "has_console_access": False, "mfa_enabled": True},
    )
    admin_key = CloudResource(
        id="ak-alice-001",
        resource_type=ResourceType.ACCESS_KEY,
        name="AliceAccessKey1",
        criticality=CriticalityTier.TIER_0,
        status="active",
        properties={"is_active": True},
    )
    odg.add_resource(admin_user)
    odg.add_resource(admin_key)
    # Key belongs to user: edge from key -> user
    odg.add_dependency(admin_key.id, admin_user.id, EdgeType.ATTACHED_TO)

    # 2. Web Target Group with 2 Replicas (MinHealthyReplicas = 2)
    target_group = CloudResource(
        id="tg-web-production",
        resource_type=ResourceType.TARGET_GROUP,
        name="ProductionWebTG",
        criticality=CriticalityTier.TIER_0,
        status="active",
        properties={"min_healthy_replicas": 2, "health_check_port_open": True},
    )
    instance_1 = CloudResource(
        id="i-web-node-01",
        resource_type=ResourceType.EC2_INSTANCE,
        name="WebNode1",
        criticality=CriticalityTier.TIER_0,
        status="running",
    )
    instance_2 = CloudResource(
        id="i-web-node-02",
        resource_type=ResourceType.EC2_INSTANCE,
        name="WebNode2",
        criticality=CriticalityTier.TIER_0,
        status="running",
    )
    odg.add_resource(target_group)
    odg.add_resource(instance_1)
    odg.add_resource(instance_2)
    odg.add_dependency(instance_1.id, target_group.id, EdgeType.MEMBER_OF)
    odg.add_dependency(instance_2.id, target_group.id, EdgeType.MEMBER_OF)

    # 3. CloudTrail Telemetry
    trail = CloudResource(
        id="trail-main-audit",
        resource_type=ResourceType.CLOUDTRAIL_TRAIL,
        name="MainAuditTrail",
        criticality=CriticalityTier.TIER_0,
        status="active",
    )
    log_bucket = CloudResource(
        id="bucket-audit-logs",
        resource_type=ResourceType.S3_BUCKET,
        name="AuditLogBucket",
        criticality=CriticalityTier.TIER_0,
        status="active",
        properties={"allows_cloudtrail_delivery": True},
    )
    kms_key = CloudResource(
        id="kms-audit-key",
        resource_type=ResourceType.KMS_KEY,
        name="AuditEncryptionKey",
        criticality=CriticalityTier.TIER_0,
        status="active",
        properties={"allows_cloudtrail_kms": True},
    )
    odg.add_resource(trail)
    odg.add_resource(log_bucket)
    odg.add_resource(kms_key)
    odg.add_dependency(trail.id, log_bucket.id, EdgeType.DELIVERS_TO)
    odg.add_dependency(trail.id, kms_key.id, EdgeType.ENCRYPTED_BY)

    return odg


def test_odg_graph_cloning_isolation(base_odg: OperationalDependencyGraph):
    """Verify that cloning produces an isolated graph that does not mutate the original."""
    clone = base_odg.clone()
    clone.remove_resource("i-web-node-01")

    assert clone.get_resource("i-web-node-01") is None
    assert base_odg.get_resource("i-web-node-01") is not None


def test_safe_legitimate_action_allowed(base_odg: OperationalDependencyGraph):
    """
    Scenario: Adding a 3rd instance to the target group and isolating it.
    With 3 nodes and min_healthy=2, isolating 1 leaves 2 healthy nodes.
    Expected: ALLOW.
    """
    instance_3 = CloudResource(
        id="i-web-node-03",
        resource_type=ResourceType.EC2_INSTANCE,
        name="WebNode3",
        criticality=CriticalityTier.TIER_0,
        status="running",
    )
    base_odg.add_resource(instance_3)
    base_odg.add_dependency(instance_3.id, "tg-web-production", EdgeType.MEMBER_OF)

    governor = SentinelGuardGovernor(base_odg)
    action = RemediationAction(
        action_type=ActionType.ISOLATE_INSTANCE,
        target_resource_id="i-web-node-03",
        rationale="Compromised web node with lateral movement detected",
    )

    decision = governor.evaluate_action(action)
    assert decision.decision == DecisionType.ALLOW
    assert decision.executed_action.action_type == ActionType.ISOLATE_INSTANCE
    assert decision.invariant_results["I_Avail"] is True


def test_operational_trap_1_sole_admin_lockout(base_odg: OperationalDependencyGraph):
    """
    Operational Trap 1:
    AI detects suspicious activity on Alice's access key and proposes revoking it.
    However, Alice is the only reachable administrator with no secondary emergency role.
    Expected: Fails I_Admin -> REQUEST_APPROVAL (prevents total organizational lockout).
    """
    governor = SentinelGuardGovernor(base_odg)
    action = RemediationAction(
        action_type=ActionType.REVOKE_ACCESS_KEY,
        target_resource_id="ak-alice-001",
        rationale="Anomalous API calls detected from unknown IP",
    )

    decision = governor.evaluate_action(action)
    assert decision.decision == DecisionType.REQUEST_APPROVAL
    assert decision.invariant_results["I_Admin"] is False
    assert any("lockout" in v.message.lower() for v in decision.violations)
    assert decision.executed_action is None


def test_operational_trap_2_quorum_service_outage_modified(base_odg: OperationalDependencyGraph):
    """
    Operational Trap 2:
    Target group has 2 nodes with MinHealthyReplicas = 2.
    AI proposes isolating Node 1.
    Isolating it drops healthy capacity to 1 < 2, violating I_Avail.
    Governor verifies mitigation lattice and selects ATTACH_SCOPED_EGRESS_FILTER.
    Expected: MODIFY (preserves service availability while neutralizing threat).
    """
    governor = SentinelGuardGovernor(base_odg)
    action = RemediationAction(
        action_type=ActionType.ISOLATE_INSTANCE,
        target_resource_id="i-web-node-01",
        rationale="Attacker cryptominer process running on web node",
    )

    decision = governor.evaluate_action(action)
    assert decision.decision == DecisionType.MODIFY
    assert decision.executed_action.action_type == ActionType.ATTACH_SCOPED_EGRESS_FILTER
    assert decision.executed_action.parameters["preserve_health_checks"] is True
    assert decision.invariant_results["I_Avail"] is False  # Original action failed I_Avail


def test_operational_trap_3_telemetry_blindness(base_odg: OperationalDependencyGraph):
    """
    Operational Trap 3:
    AI proposes removing permission policy or modifying S3 bucket that severs CloudTrail delivery.
    Expected: Fails I_Telem -> Selected verified mitigation (SCOPE_PERMISSION) or REQUEST_APPROVAL.
    """
    governor = SentinelGuardGovernor(base_odg)
    action = RemediationAction(
        action_type=ActionType.REMOVE_PERMISSION,
        target_resource_id="bucket-audit-logs",
        parameters={"block_service_delivery": True},
        rationale="Attempting to quarantine compromised audit bucket",
    )

    decision = governor.evaluate_action(action)
    assert decision.decision in {DecisionType.REQUEST_APPROVAL, DecisionType.MODIFY}
    assert decision.invariant_results["I_Telem"] is False


def test_overt_unauthorized_action_blocked(base_odg: OperationalDependencyGraph):
    """
    Scenario: Injected prompt or rogue agent requests an unapproved action type.
    Expected: BLOCK.
    """
    governor = SentinelGuardGovernor(base_odg)
    action = RemediationAction(
        action_type=ActionType.ISOLATE_INSTANCE,
        target_resource_id="i-web-node-01",
    )

    # Restrict authorized actions to only key revocations
    decision = governor.evaluate_action(
        action, authorized_actions=[ActionType.REVOKE_ACCESS_KEY]
    )
    assert decision.decision == DecisionType.BLOCK
    assert "unauthorized" in decision.reason.lower()


def test_audit_ledger_tamper_evident_integrity(base_odg: OperationalDependencyGraph):
    """
    Verify that the audit ledger maintains cryptographic chain integrity.
    """
    governor = SentinelGuardGovernor(base_odg)
    action = RemediationAction(
        action_type=ActionType.ISOLATE_INSTANCE,
        target_resource_id="i-web-node-01",
    )

    decision = governor.evaluate_action(action)
    assert decision.audit_hash is not None
    assert len(governor.audit_ledger.chain) == 1
    assert governor.audit_ledger.verify_integrity() is True
