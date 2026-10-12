"""
Operational Dependency Graph (ODG) implemented using NetworkX.
Maintains cloud resources, their topology, relationships, and operational constraints.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from sentinelguard.core.schemas import (
    CloudResource,
    CriticalityTier,
    EdgeType,
    ResourceType,
)


class OperationalDependencyGraph:
    """
    Directed property graph representing cloud resources and their dependencies.
    Provides query methods for blast radius and invariant evaluation.
    """

    def __init__(self) -> None:
        self.g: nx.DiGraph = nx.DiGraph()

    def add_resource(self, resource: CloudResource) -> None:
        """Add or update a cloud resource node in the ODG."""
        self.g.add_node(
            resource.id,
            resource=resource,
            resource_type=resource.resource_type.value,
            criticality=resource.criticality.value,
            status=resource.status,
            account_id=resource.account_id,
        )

    def get_resource(self, resource_id: str) -> Optional[CloudResource]:
        """Retrieve a cloud resource by its identifier."""
        if self.g.has_node(resource_id):
            return self.g.nodes[resource_id].get("resource")
        return None

    def remove_resource(self, resource_id: str) -> None:
        """Remove a resource node and its associated edges."""
        if self.g.has_node(resource_id):
            self.g.remove_node(resource_id)

    def add_dependency(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        properties: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Add a directed dependency edge from source to target.
        Meaning: source depends on / routes to / is attached to target.
        """
        if not self.g.has_node(source_id) or not self.g.has_node(target_id):
            raise KeyError(
                f"Both nodes must exist in ODG to add edge: '{source_id}' -> '{target_id}'"
            )
        props = properties or {}
        self.g.add_edge(source_id, target_id, edge_type=edge_type.value, **props)

    def remove_dependency(self, source_id: str, target_id: str) -> None:
        """Remove a directed dependency edge if it exists."""
        if self.g.has_edge(source_id, target_id):
            self.g.remove_edge(source_id, target_id)

    def clone(self) -> OperationalDependencyGraph:
        """
        Produce an independent deep-copy of the graph for speculative simulation.
        Mutations on the clone will not alter this graph.
        """
        new_odg = OperationalDependencyGraph()
        # Deep copy nodes and resources
        for node_id, data in self.g.nodes(data=True):
            resource_copy = data["resource"].model_copy(deep=True)
            new_odg.add_resource(resource_copy)
        # Deep copy edges
        for u, v, data in self.g.edges(data=True):
            edge_type = EdgeType(data["edge_type"])
            edge_props = {k: v_val for k, v_val in data.items() if k != "edge_type"}
            new_odg.add_dependency(u, v, edge_type, copy.deepcopy(edge_props))
        return new_odg

    # -----------------------------------------------------------------------
    # Operational Queries for Invariant Checks
    # -----------------------------------------------------------------------

    def get_resources_by_type(self, resource_type: ResourceType) -> List[CloudResource]:
        """Find all resources of a given type."""
        results: List[CloudResource] = []
        for _, data in self.g.nodes(data=True):
            res: CloudResource = data.get("resource")
            if res and res.resource_type == resource_type:
                results.append(res)
        return results

    def get_active_admin_paths(
        self, account_id: str, excluding_resource_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Find independent, reachable administrative recovery paths for an account.
        An admin path is defined by:
        1. An active IAM User or Role with admin privileges (AdministratorAccess).
        2. Must have active credentials (e.g. an active access key or assumed role).
        3. Must have reachability (e.g. independent MFA, console or API access).
        4. Excludes the specified resource (if testing revocation of that resource).
        """
        paths: List[Dict[str, Any]] = []

        # Check IAM Users with Admin
        admin_users = [
            res for res in self.get_resources_by_type(ResourceType.IAM_USER)
            if res.account_id == account_id and res.is_active()
            and res.properties.get("is_admin", False)
        ]

        for user in admin_users:
            if user.id == excluding_resource_id:
                continue

            # Look for active keys attached to user
            active_keys = []
            for pred in self.g.predecessors(user.id):
                res = self.get_resource(pred)
                if (
                    res and res.resource_type == ResourceType.ACCESS_KEY
                    and res.id != excluding_resource_id
                    and res.is_active()
                ):
                    active_keys.append(res)

            # Check if user has active console password or active key
            has_valid_credentials = len(active_keys) > 0 or user.properties.get("has_console_access", False)
            if has_valid_credentials:
                paths.append({
                    "type": "iam_user",
                    "id": user.id,
                    "name": user.name,
                    "is_break_glass": user.properties.get("is_break_glass", False),
                    "active_keys": [k.id for k in active_keys],
                    "independent_mfa": user.properties.get("mfa_enabled", False),
                })

        # Check Break-Glass / Emergency IAM Roles
        admin_roles = [
            res for res in self.get_resources_by_type(ResourceType.IAM_ROLE)
            if res.account_id == account_id and res.is_active()
            and res.properties.get("is_admin", False)
        ]

        for role in admin_roles:
            if role.id == excluding_resource_id:
                continue
            # Role must have trusted recovery identity provider or active assume role path
            if role.properties.get("is_emergency_recovery", False):
                paths.append({
                    "type": "emergency_role",
                    "id": role.id,
                    "name": role.name,
                    "is_break_glass": True,
                    "trusted_idp": role.properties.get("trusted_idp", "aws_iam"),
                    "independent_mfa": role.properties.get("mfa_required", True),
                })

        return paths

    def get_target_group_health(self, target_group_id: str) -> Dict[str, Any]:
        """
        Evaluate healthy instances and capacity for a target group.
        """
        tg = self.get_resource(target_group_id)
        if not tg:
            return {"exists": False, "healthy_count": 0, "min_healthy": 1}

        min_healthy = tg.properties.get("min_healthy_replicas", 1)
        healthy_instances: List[CloudResource] = []

        # Members are connected via MEMBER_OF edge from instance -> target_group
        for pred in self.g.predecessors(target_group_id):
            edge_data = self.g.get_edge_data(pred, target_group_id)
            if edge_data and edge_data.get("edge_type") == EdgeType.MEMBER_OF.value:
                instance = self.get_resource(pred)
                if instance and instance.is_active():
                    # Check if instance is in healthy status and not isolated
                    if instance.status in {"active", "running", "healthy"}:
                        healthy_instances.append(instance)

        # Check health-check network connectivity
        # If any attached security group blocks health check port, ingress fails
        health_check_open = tg.properties.get("health_check_port_open", True)

        return {
            "exists": True,
            "target_group": tg,
            "min_healthy": min_healthy,
            "healthy_count": len(healthy_instances),
            "healthy_instances": [i.id for i in healthy_instances],
            "health_check_open": health_check_open,
            "is_quorum_preserved": len(healthy_instances) >= min_healthy,
        }

    def check_telemetry_health(self) -> Dict[str, Dict[str, Any]]:
        """
        Evaluate resource-specific telemetry continuity for:
        1. CloudTrail
        2. VPC Flow Logs
        3. CloudWatch Agents
        """
        telemetry_status: Dict[str, Dict[str, Any]] = {}

        # 1. CloudTrail Trails
        trails = self.get_resources_by_type(ResourceType.CLOUDTRAIL_TRAIL)
        trail_results = []
        for trail in trails:
            if not trail.is_active():
                trail_results.append({"id": trail.id, "healthy": False, "reason": "Trail inactive"})
                continue

            # Verify destination S3 bucket
            bucket_ok = False
            kms_ok = True
            for succ in self.g.successors(trail.id):
                edge = self.g.get_edge_data(trail.id, succ)
                edge_type = edge.get("edge_type") if edge else None
                dest_res = self.get_resource(succ)

                if edge_type == EdgeType.DELIVERS_TO.value and dest_res:
                    if dest_res.resource_type == ResourceType.S3_BUCKET and dest_res.is_active():
                        # Check bucket policy permits CloudTrail
                        if dest_res.properties.get("allows_cloudtrail_delivery", True):
                            bucket_ok = True

                if edge_type == EdgeType.ENCRYPTED_BY.value and dest_res:
                    if dest_res.resource_type == ResourceType.KMS_KEY:
                        if not dest_res.is_active() or dest_res.properties.get("allows_cloudtrail_kms", True) is False:
                            kms_ok = False

            is_healthy = bucket_ok and kms_ok
            reason = "OK" if is_healthy else ("Missing bucket write permissions" if not bucket_ok else "KMS key disabled/unauthorized")
            trail_results.append({"id": trail.id, "healthy": is_healthy, "reason": reason})

        telemetry_status["cloudtrail"] = {
            "healthy": all(t["healthy"] for t in trail_results) if trail_results else True,
            "trails": trail_results,
        }

        # 2. VPC Flow Logs
        flow_logs = self.get_resources_by_type(ResourceType.VPC_FLOW_LOG)
        flow_results = []
        for flow_log in flow_logs:
            if not flow_log.is_active():
                flow_results.append({"id": flow_log.id, "healthy": False, "reason": "Flow log disabled"})
                continue

            has_delivery_role = flow_log.properties.get("has_delivery_role", True)
            has_destination = flow_log.properties.get("destination_accessible", True)
            is_healthy = has_delivery_role and has_destination
            reason = "OK" if is_healthy else "Missing delivery role or destination inaccessible"
            flow_results.append({"id": flow_log.id, "healthy": is_healthy, "reason": reason})

        telemetry_status["vpc_flow_logs"] = {
            "healthy": all(f["healthy"] for f in flow_results) if flow_results else True,
            "logs": flow_results,
        }

        # 3. CloudWatch Host Agents
        cw_agents = self.get_resources_by_type(ResourceType.CLOUDWATCH_AGENT)
        agent_results = []
        for agent in cw_agents:
            if not agent.is_active():
                agent_results.append({"id": agent.id, "healthy": False, "reason": "Agent stopped"})
                continue

            # Check instance role permission and network route to CloudWatch endpoint
            has_log_perm = agent.properties.get("has_put_log_permission", True)
            network_egress = agent.properties.get("cloudwatch_endpoint_accessible", True)
            is_healthy = has_log_perm and network_egress
            reason = "OK" if is_healthy else ("Missing logs:PutLogEvents" if not has_log_perm else "No route to CloudWatch endpoint")
            agent_results.append({"id": agent.id, "healthy": is_healthy, "reason": reason})

        telemetry_status["cloudwatch_agents"] = {
            "healthy": all(a["healthy"] for a in agent_results) if agent_results else True,
            "agents": agent_results,
        }

        return telemetry_status

    def compute_blast_radius(self, resource_id: str) -> List[str]:
        """
        Calculate downstream resources dependent on this resource (transitive successors & predecessors).
        """
        if not self.g.has_node(resource_id):
            return []

        # Reachable descendants in dependency graph
        descendants = nx.descendants(self.g, resource_id)
        # Immediate predecessors that rely on this node
        predecessors = set(self.g.predecessors(resource_id))
        blast = list(descendants.union(predecessors))
        return blast
