"""
Simulated Cloud Environment for SentinelGuard (Phase 7).
Models live AWS cloud resources, dependencies, out-of-band state changes,
and controlled action execution with cryptographic state fingerprinting.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional

from sentinelguard.core.graph import OperationalDependencyGraph
from sentinelguard.core.schemas import (
    ActionType,
    CloudResource,
    EdgeType,
    RemediationAction,
)
from sentinelguard.execution.schemas import ExecutionResult


class SimulatedCloudEnvironment:
    """
    In-memory representation of the live cloud environment.
    Maintains authoritative state, computes deterministic cryptographic state fingerprints,
    and executes remediation actions under controlled simulation.
    """

    def __init__(self, initial_graph: Optional[OperationalDependencyGraph] = None) -> None:
        self.live_graph = initial_graph.clone() if initial_graph else OperationalDependencyGraph()
        self._simulated_failure: Optional[Dict[str, str]] = None

    def get_state_snapshot(self) -> OperationalDependencyGraph:
        """Return a deep, isolated copy of current cloud topology."""
        return self.live_graph.clone()

    def get_resource(self, resource_id: str) -> Optional[CloudResource]:
        """Fetch live resource state."""
        return self.live_graph.get_resource(resource_id)

    def compute_state_fingerprint(self) -> str:
        """
        Compute a deterministic SHA-256 fingerprint representing the exact
        topological state and properties of all live cloud resources and dependencies.
        """
        resources_summary = []
        for node_id, data in sorted(self.live_graph.g.nodes(data=True)):
            res = data.get("resource")
            if not res:
                continue
            props_sorted = sorted(
                [(k, str(v)) for k, v in res.properties.items() if not k.startswith("_")]
            )
            resources_summary.append({
                "id": res.id,
                "type": res.resource_type.value,
                "status": res.status,
                "criticality": res.criticality.value,
                "properties": props_sorted,
            })

        edges_summary = []
        for u, v, data in sorted(self.live_graph.g.edges(data=True)):
            edge_type = data.get("edge_type")
            edges_summary.append({
                "u": u,
                "v": v,
                "type": edge_type.value if hasattr(edge_type, "value") else str(edge_type),
            })

        state_repr = json.dumps({"resources": resources_summary, "edges": edges_summary}, sort_keys=True)
        return hashlib.sha256(state_repr.encode("utf-8")).hexdigest()

    def inject_api_failure(self, error_code: str = "InternalError", message: str = "AWS API Exception") -> None:
        """Simulate transient AWS cloud API failure on next execution call."""
        self._simulated_failure = {"error_code": error_code, "message": message}

    def clear_injected_failures(self) -> None:
        """Clear simulated API failures."""
        self._simulated_failure = None

    def mutate_resource_out_of_band(
        self,
        resource_id: str,
        new_status: Optional[str] = None,
        new_properties: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Simulate an out-of-band environment change (e.g., operator manual change or concurrent failure)
        occurring between verification time and execution dispatch time.
        """
        res = self.live_graph.get_resource(resource_id)
        if not res:
            return False

        if new_status is not None:
            res.status = new_status
        if new_properties:
            res.properties.update(new_properties)
        return True

    def execute_action(self, action: RemediationAction) -> ExecutionResult:
        """
        Apply remediation action to live simulated cloud resources.
        Guarantees zero mutation to live AWS infrastructure.
        """
        pre_hash = self.compute_state_fingerprint()

        # 1. Check for injected API failure
        if self._simulated_failure:
            err = self._simulated_failure
            self._simulated_failure = None
            return ExecutionResult(
                success=False,
                action=action,
                pre_state_hash=pre_hash,
                post_state_hash=pre_hash,
                message=f"Cloud API Execution Failed: {err['message']}",
                error_code=err["error_code"],
                timestamp=time.time(),
            )

        # 2. Check if target resource exists in live environment
        target = self.live_graph.get_resource(action.target_resource_id)
        if not target:
            return ExecutionResult(
                success=False,
                action=action,
                pre_state_hash=pre_hash,
                post_state_hash=pre_hash,
                message=f"Target resource '{action.target_resource_id}' not found in live cloud environment.",
                error_code="ResourceNotFound",
                timestamp=time.time(),
            )

        # 3. Apply state change based on action type
        if action.action_type == ActionType.ISOLATE_INSTANCE:
            target.status = "isolated"
            target.properties["is_isolated"] = True
            # Sever inbound health-checks if standard isolate
            target.properties["health_check_port_open"] = False

        elif action.action_type == ActionType.ATTACH_SCOPED_EGRESS_FILTER:
            target.properties["scoped_egress_filter_attached"] = True
            target.properties["c2_egress_blocked"] = True
            # Preserves health check connectivity
            target.properties["health_check_port_open"] = True

        elif action.action_type == ActionType.DEREGISTER_AND_DRAIN:
            target.status = "draining"
            target.properties["draining"] = True
            # Remove from target groups
            edges_to_remove = []
            for u, v, data in self.live_graph.g.out_edges(target.id, data=True):
                edge_t = data.get("edge_type")
                if edge_t == EdgeType.MEMBER_OF.value:
                    edges_to_remove.append((u, v))
            for u, v in edges_to_remove:
                self.live_graph.g.remove_edge(u, v)

        elif action.action_type == ActionType.REVOKE_ACCESS_KEY:
            target.status = "revoked"
            target.properties["is_active"] = False

        elif action.action_type == ActionType.REMOVE_PERMISSION:
            if action.parameters.get("block_service_delivery"):
                target.properties["allows_cloudtrail_delivery"] = False
            target.properties["permission_removed"] = True

        elif action.action_type == ActionType.SCOPE_PERMISSION_TO_RESOURCE:
            target.properties["scoped_to_resource"] = True

        post_hash = self.compute_state_fingerprint()

        return ExecutionResult(
            success=True,
            action=action,
            pre_state_hash=pre_hash,
            post_state_hash=post_hash,
            message=f"Action '{action.action_type.value}' successfully executed on target '{action.target_resource_id}'.",
            timestamp=time.time(),
        )
