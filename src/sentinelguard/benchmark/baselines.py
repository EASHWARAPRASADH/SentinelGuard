"""
The Four Evaluation Baselines for CloudGuard-Bench:
1. Config 1: Unchecked LLM (no verification, dispatches whatever was proposed)
2. Config 2: Static Policy Gate (syntax & IAM authorization whitelist, no dependency awareness)
3. Config 3: Static Policy + Dependency Check (checks static criticality tags, but no counterfactual simulation or mitigation selection)
4. Config 4: SentinelGuard (state-aware counterfactual verification + verified mitigation selection)
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from sentinelguard.benchmark.scenario_schema import BenchmarkScenario
from sentinelguard.core.engine import SentinelGuardGovernor
from sentinelguard.core.graph import OperationalDependencyGraph
from sentinelguard.core.schemas import (
    ActionType,
    CriticalityTier,
    DecisionType,
    GovernanceDecision,
    RemediationAction,
)


class BaselineDecision:
    def __init__(
        self,
        decision: DecisionType,
        executed_action: Optional[RemediationAction],
        latency_ms: float,
        reason: str,
    ) -> None:
        self.decision = decision
        self.executed_action = executed_action
        self.latency_ms = latency_ms
        self.reason = reason


# ---------------------------------------------------------------------------
# Config 1: Unchecked LLM Baseline
# ---------------------------------------------------------------------------

class UncheckedLLMBaseline:
    """Dispatches all AI proposed actions without pre-execution policy checks."""

    @staticmethod
    def evaluate(odg: OperationalDependencyGraph, scenario: BenchmarkScenario) -> BaselineDecision:
        t0 = time.perf_counter()
        action_data = scenario.proposed_action
        try:
            act_type = ActionType(action_data["action_type"])
        except ValueError:
            # Unknown string, unchecked baseline still attempts execution
            act_type = ActionType.ISOLATE_INSTANCE

        action = RemediationAction(
            action_type=act_type,
            target_resource_id=action_data["target_resource_id"],
            rationale=action_data.get("rationale", ""),
        )
        latency = (time.perf_counter() - t0) * 1000.0
        return BaselineDecision(
            decision=DecisionType.ALLOW,
            executed_action=action,
            latency_ms=latency,
            reason="Unchecked baseline blindly permits action.",
        )


# ---------------------------------------------------------------------------
# Config 2: Static Policy Gate
# ---------------------------------------------------------------------------

class StaticPolicyBaseline:
    """Evaluates action syntax and authorization against a static policy whitelist."""

    APPROVED_ACTIONS = {
        ActionType.ISOLATE_INSTANCE.value,
        ActionType.REVOKE_ACCESS_KEY.value,
        ActionType.REMOVE_PERMISSION.value,
    }

    @classmethod
    def evaluate(cls, odg: OperationalDependencyGraph, scenario: BenchmarkScenario) -> BaselineDecision:
        t0 = time.perf_counter()
        action_data = scenario.proposed_action
        raw_act_type = action_data["action_type"]

        # Check authorization against static whitelist
        if raw_act_type not in cls.APPROVED_ACTIONS:
            latency = (time.perf_counter() - t0) * 1000.0
            return BaselineDecision(
                decision=DecisionType.BLOCK,
                executed_action=None,
                latency_ms=latency,
                reason=f"Action '{raw_act_type}' is not in authorized policy catalog.",
            )

        target_res = odg.get_resource(action_data["target_resource_id"])
        if not target_res:
            latency = (time.perf_counter() - t0) * 1000.0
            return BaselineDecision(
                decision=DecisionType.BLOCK,
                executed_action=None,
                latency_ms=latency,
                reason="Target resource does not exist.",
            )

        # Has no dependency awareness: permits action regardless of dependencies
        act = RemediationAction(
            action_type=ActionType(raw_act_type),
            target_resource_id=target_res.id,
            parameters=action_data.get("parameters", {}),
            rationale=action_data.get("rationale", ""),
        )
        latency = (time.perf_counter() - t0) * 1000.0
        return BaselineDecision(
            decision=DecisionType.ALLOW,
            executed_action=act,
            latency_ms=latency,
            reason="Action syntax and catalog permissions verified.",
        )


# ---------------------------------------------------------------------------
# Config 3: Static Policy Gate + Operational Dependency Checks
# (Without Counterfactual Simulation or Mitigation Selection)
# ---------------------------------------------------------------------------

class StaticPolicyWithDependencyBaseline:
    """
    Checks static policy AND inspects immediate resource criticality/tags,
    but performs NO counterfactual graph projection or mitigation selection.
    """

    APPROVED_ACTIONS = {
        ActionType.ISOLATE_INSTANCE.value,
        ActionType.REVOKE_ACCESS_KEY.value,
        ActionType.REMOVE_PERMISSION.value,
    }

    @classmethod
    def evaluate(cls, odg: OperationalDependencyGraph, scenario: BenchmarkScenario) -> BaselineDecision:
        t0 = time.perf_counter()
        action_data = scenario.proposed_action
        raw_act_type = action_data["action_type"]

        # 1. Authorization check
        if raw_act_type not in cls.APPROVED_ACTIONS:
            latency = (time.perf_counter() - t0) * 1000.0
            return BaselineDecision(
                decision=DecisionType.BLOCK,
                executed_action=None,
                latency_ms=latency,
                reason=f"Action '{raw_act_type}' not in authorized catalog.",
            )

        target_res = odg.get_resource(action_data["target_resource_id"])
        if not target_res:
            latency = (time.perf_counter() - t0) * 1000.0
            return BaselineDecision(
                decision=DecisionType.BLOCK,
                executed_action=None,
                latency_ms=latency,
                reason="Target resource does not exist.",
            )

        # 2. Static dependency check (checks static attributes without simulating post-action state)
        # Rigid heuristic: if resource is Tier-0 or has active dependencies, blindly BLOCK
        if target_res.criticality == CriticalityTier.TIER_0 or target_res.properties.get("is_admin", False):
            latency = (time.perf_counter() - t0) * 1000.0
            return BaselineDecision(
                decision=DecisionType.BLOCK,
                executed_action=None,
                latency_ms=latency,
                reason="Static dependency check: resource flagged as Tier-0 / Critical. Blocking.",
            )

        # If key belongs to a Tier-0 admin, check if user is Tier-0
        for succ in odg.g.successors(target_res.id):
            parent = odg.get_resource(succ)
            if parent and (parent.criticality == CriticalityTier.TIER_0 or parent.properties.get("is_admin", False)):
                latency = (time.perf_counter() - t0) * 1000.0
                return BaselineDecision(
                    decision=DecisionType.BLOCK,
                    executed_action=None,
                    latency_ms=latency,
                    reason="Static dependency check: parent resource is Tier-0. Blocking.",
                )

        act = RemediationAction(
            action_type=ActionType(raw_act_type),
            target_resource_id=target_res.id,
            parameters=action_data.get("parameters", {}),
            rationale=action_data.get("rationale", ""),
        )
        latency = (time.perf_counter() - t0) * 1000.0
        return BaselineDecision(
            decision=DecisionType.ALLOW,
            executed_action=act,
            latency_ms=latency,
            reason="Static policy and dependency checks passed.",
        )


# ---------------------------------------------------------------------------
# Config 4: SentinelGuard Governor (Proposed System)
# ---------------------------------------------------------------------------

class SentinelGuardEvaluator:
    """Executes the full 10-step verified remediation lifecycle."""

    @staticmethod
    def evaluate(odg: OperationalDependencyGraph, scenario: BenchmarkScenario) -> BaselineDecision:
        t0 = time.perf_counter()
        governor = SentinelGuardGovernor(odg)
        action_data = scenario.proposed_action

        try:
            act_type = ActionType(action_data["action_type"])
        except ValueError:
            # Unauthorized or malformed action string
            latency = (time.perf_counter() - t0) * 1000.0
            return BaselineDecision(
                decision=DecisionType.BLOCK,
                executed_action=None,
                latency_ms=latency,
                reason=f"Action '{action_data['action_type']}' not recognized in schema.",
            )

        action = RemediationAction(
            action_type=act_type,
            target_resource_id=action_data["target_resource_id"],
            parameters=action_data.get("parameters", {}),
            rationale=action_data.get("rationale", ""),
        )

        decision = governor.evaluate_action(action)
        latency = (time.perf_counter() - t0) * 1000.0

        return BaselineDecision(
            decision=decision.decision,
            executed_action=decision.executed_action,
            latency_ms=latency,
            reason=decision.reason,
        )
