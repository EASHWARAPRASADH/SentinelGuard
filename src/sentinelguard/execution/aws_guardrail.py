"""
AWS Execution Guardrail for SentinelGuard (Phase 7).
Enforces strict fail-closed safety barriers against unintended live AWS cloud mutations.
Guarantees simulation-only mode by default.
"""

from __future__ import annotations

import os
from typing import Any, Dict


class AWSExecutionGuardrail:
    """
    Enforces safety barriers to prevent unintended live AWS cloud mutations.
    """

    ENV_VAR = "SENTINELGUARD_ALLOW_LIVE_AWS_EXECUTION"

    @classmethod
    def is_live_execution_permitted(cls) -> bool:
        """
        Check if live AWS execution is explicitly permitted via environment flags.
        Defaults strictly to False.
        """
        val = os.getenv(cls.ENV_VAR, "false").strip().lower()
        return val in {"true", "1", "yes", "enabled"}

    @classmethod
    def assert_simulation_safety(cls, requested_mode: str = "SIMULATED") -> None:
        """
        Assert that the requested execution mode respects safety boundaries.
        """
        if requested_mode.upper() == "LIVE":
            if not cls.is_live_execution_permitted():
                raise PermissionError(
                    f"Live AWS execution is disabled by SentinelGuard safety policy. "
                    f"Set {cls.ENV_VAR}=true with authorized IAM credentials to enable live dispatch. "
                    f"Execution aborted fail-closed."
                )
