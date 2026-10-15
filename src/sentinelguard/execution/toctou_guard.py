"""
TOCTOU Guard (Time-of-Check to Time-of-Use) for SentinelGuard (Phase 7).
Validates that the cloud environment state has not drifted between Governor verification
and remediation execution dispatch. Prevents execution on stale assumptions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from sentinelguard.core.schemas import GovernanceDecision
from sentinelguard.execution.environment import SimulatedCloudEnvironment
from sentinelguard.execution.schemas import TOCTOUValidationResult


class TOCTOUGuard:
    """
    Validates pre-execution environmental state consistency against the verification baseline.
    """

    @classmethod
    def validate_pre_execution(
        cls,
        environment: SimulatedCloudEnvironment,
        baseline_fingerprint: str,
        decision: Optional[GovernanceDecision] = None,
        tracked_resources_snapshot: Optional[Dict[str, Dict[str, Any]]] = None,
        baseline_graph: Optional[Any] = None,
    ) -> TOCTOUValidationResult:
        """
        Verify that the current cloud state matches the baseline state captured when the Governor evaluated the action.
        """
        current_fingerprint = environment.compute_state_fingerprint()

        # 1. Exact cryptographic state match
        if current_fingerprint == baseline_fingerprint:
            return TOCTOUValidationResult(
                valid=True,
                drift_detected=False,
                baseline_hash=baseline_fingerprint,
                current_hash=current_fingerprint,
            )

        # 2. State mismatch detected - identify drifted resources
        drifted_resources: List[str] = []
        if baseline_graph:
            for node_id, data in baseline_graph.g.nodes(data=True):
                base_res = data.get("resource")
                if not base_res:
                    continue
                live_res = environment.get_resource(node_id)
                if not live_res:
                    drifted_resources.append(f"{node_id} (deleted)")
                elif live_res.status != base_res.status:
                    drifted_resources.append(f"{node_id} (status: {base_res.status} -> {live_res.status})")
                elif live_res.properties != base_res.properties:
                    drifted_resources.append(f"{node_id} (properties modified)")

        elif tracked_resources_snapshot:
            for res_id, snap_props in tracked_resources_snapshot.items():
                live_res = environment.get_resource(res_id)
                if not live_res:
                    drifted_resources.append(f"{res_id} (deleted)")
                elif live_res.status != snap_props.get("status"):
                    drifted_resources.append(f"{res_id} (status: {snap_props.get('status')} -> {live_res.status})")
                elif live_res.properties != snap_props.get("properties"):
                    drifted_resources.append(f"{res_id} (properties modified)")

        # If decision provides blast radius, check those as well
        if decision and decision.blast_radius:
            for res_id in decision.blast_radius:
                if res_id not in [r.split()[0] for r in drifted_resources]:
                    live_res = environment.get_resource(res_id)
                    if not live_res:
                        drifted_resources.append(f"{res_id} (deleted)")

        if not drifted_resources:
            drifted_resources.append("topology_or_dependency_graph_drift")

        return TOCTOUValidationResult(
            valid=False,
            drift_detected=True,
            baseline_hash=baseline_fingerprint,
            current_hash=current_fingerprint,
            reason=(
                f"TOCTOU Pre-Execution Check Failed: Environmental state drift detected between "
                f"Governor verification and dispatch. Drifted resources: {', '.join(drifted_resources)}. "
                f"Execution aborted to prevent out-of-order operational disruption."
            ),
            drifted_resources=drifted_resources,
        )
