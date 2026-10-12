"""
Core schemas for SentinelGuard: cloud resources, dependency edges,
actions, invariants, and governance decisions.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ResourceType(str, Enum):
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    ACCESS_KEY = "access_key"
    EC2_INSTANCE = "ec2_instance"
    SECURITY_GROUP = "security_group"
    TARGET_GROUP = "target_group"
    LOAD_BALANCER = "load_balancer"
    VPC_SUBNET = "vpc_subnet"
    CLOUDTRAIL_TRAIL = "cloudtrail_trail"
    VPC_FLOW_LOG = "vpc_flow_log"
    CLOUDWATCH_AGENT = "cloudwatch_agent"
    S3_BUCKET = "s3_bucket"
    KMS_KEY = "kms_key"
    IAM_POLICY = "iam_policy"


class CriticalityTier(str, Enum):
    TIER_0 = "tier_0"  # Mission critical (e.g., Core DB, Auth service, Break-Glass)
    TIER_1 = "tier_1"  # Business critical (e.g., Customer API, Web frontends)
    TIER_2 = "tier_2"  # Internal services (e.g., Analytics, staging)
    TIER_3 = "tier_3"  # Dev/Test/Ephemeral


class EdgeType(str, Enum):
    ATTACHED_TO = "attached_to"
    ROUTES_TO = "routes_to"
    DELIVERS_TO = "delivers_to"
    ENCRYPTED_BY = "encrypted_by"
    MEMBER_OF = "member_of"
    PROTECTS = "protects"
    ACTS_AS_RECOVERY_FOR = "acts_as_recovery_for"
    USES_ROLE = "uses_role"
    PERMITS_ACTION = "permits_action"


class ActionType(str, Enum):
    ISOLATE_INSTANCE = "isolate_instance"
    REVOKE_ACCESS_KEY = "revoke_access_key"
    REMOVE_PERMISSION = "remove_permission"
    # Scoped mitigations synthesized/selected by the governor
    ATTACH_SCOPED_EGRESS_FILTER = "attach_scoped_egress_filter"
    DEREGISTER_AND_DRAIN = "deregister_and_drain"
    SCOPE_PERMISSION_TO_RESOURCE = "scope_permission_to_resource"


class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    MODIFY = "MODIFY"
    REQUEST_APPROVAL = "REQUEST_APPROVAL"


class InvariantID(str, Enum):
    ADMINISTRATIVE_RECOVERY = "I_Admin"
    SERVICE_AVAILABILITY = "I_Avail"
    TELEMETRY_CONTINUITY = "I_Telem"


# ---------------------------------------------------------------------------
# Models: Resources & Actions
# ---------------------------------------------------------------------------

class CloudResource(BaseModel):
    id: str
    resource_type: ResourceType
    name: str
    account_id: str = "123456789012"
    region: str = "us-east-1"
    criticality: CriticalityTier = CriticalityTier.TIER_2
    status: str = "active"  # "active", "isolated", "revoked", "draining", "stopped"
    properties: Dict[str, Any] = Field(default_factory=dict)
    tags: Dict[str, str] = Field(default_factory=dict)

    def is_active(self) -> bool:
        return self.status.lower() in {"active", "running", "healthy", "available"}


class RemediationAction(BaseModel):
    action_type: ActionType
    target_resource_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    actor: str = "ai_investigator_agent"
    timestamp: Optional[str] = None


class InvariantViolation(BaseModel):
    invariant_id: InvariantID
    message: str
    impacted_resource_ids: List[str] = Field(default_factory=list)
    severity: str = "CRITICAL"  # "CRITICAL", "HIGH", "MEDIUM"


class InvariantCheckResult(BaseModel):
    passed: bool
    violations: List[InvariantViolation] = Field(default_factory=list)


class GovernanceDecision(BaseModel):
    decision: DecisionType
    original_action: RemediationAction
    executed_action: Optional[RemediationAction] = None
    reason: str
    invariant_results: Dict[str, bool] = Field(default_factory=dict)
    violations: List[InvariantViolation] = Field(default_factory=list)
    alternatives_evaluated: List[Dict[str, Any]] = Field(default_factory=list)
    blast_radius: List[str] = Field(default_factory=list)
    audit_hash: Optional[str] = None
