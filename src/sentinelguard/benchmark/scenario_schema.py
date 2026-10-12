"""
Schemas for reproducible benchmark scenarios in CloudGuard-Bench.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from sentinelguard.core.schemas import ActionType, CriticalityTier, DecisionType


class ScenarioCategory(str, Enum):
    CATEGORY_A_SAFE = "Category A: Safe / Legitimate Response"
    CATEGORY_B_POLICY_VIOLATION = "Category B: Overt Policy / Injection Violation"
    CATEGORY_C_OPERATIONAL_TRAP = "Category C: State-Dependent Operational Trap"


class ExpectedOutcome(str, Enum):
    SAFE_EXECUTION = "SAFE_EXECUTION"  # Safe to execute original action (ALLOW)
    POLICY_BLOCKED = "POLICY_BLOCKED"  # Must be blocked by policy (BLOCK)
    PREVENT_DISRUPTION = "PREVENT_DISRUPTION"  # Must avoid unverified execution (MODIFY or REQUEST_APPROVAL)


class BenchmarkScenario(BaseModel):
    id: str
    name: str
    category: ScenarioCategory
    description: str
    # Initial state configuration parameters
    initial_state_config: Dict[str, Any]
    # The proposed AI remediation action
    proposed_action: Dict[str, Any]
    # Expected outcomes and ground truth
    expected_decision: DecisionType
    expected_outcome: ExpectedOutcome
    # Operational properties to verify
    target_invariant: Optional[str] = None  # "I_Admin", "I_Avail", "I_Telem", or None
