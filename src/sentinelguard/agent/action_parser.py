"""
Action Parser for SentinelGuard Investigation Agent.
Safely extracts, validates, and strictly bounds LLM-generated incident assessments.
Enforces the bounded action catalogue and rejects malformed outputs and injection payloads.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional
from sentinelguard.agent.schemas import ActionProposal, InvestigationAssessment
from sentinelguard.core.schemas import ActionType


class ActionParseError(Exception):
    """Base exception for action parser validation failures."""
    pass


class MalformedJSONError(ActionParseError):
    """Raised when LLM output cannot be parsed as valid JSON."""
    pass


class UnknownActionError(ActionParseError):
    """Raised when LLM proposes an action outside the bounded catalogue."""
    pass


class MissingParameterError(ActionParseError):
    """Raised when an action proposal is missing required fields."""
    pass


class UnexpectedParameterError(ActionParseError):
    """Raised when an action proposal contains unexpected or prohibited parameters."""
    pass


class PromptInjectionDetectedError(ActionParseError):
    """Raised when adversarial injection patterns are identified."""
    pass


class ActionParser:
    """
    Validates and parses raw LLM generation strings into structured InvestigationAssessment models.
    """

    BOUNDED_ACTIONS = {
        ActionType.ISOLATE_INSTANCE.value,
        ActionType.REVOKE_ACCESS_KEY.value,
        ActionType.REMOVE_PERMISSION.value,
    }

    ALLOWED_PARAM_KEYS = {
        "policy_id",
        "permission_name",
        "grace_period_seconds",
        "preserve_health_checks",
        "block_service_delivery",
    }

    SUSPICIOUS_PARAM_PATTERNS = [
        "eval(", "exec(", "system(", "__import__", ";", "&&", "||", "`", "$(", "bash", "sh -c", "rm -rf", "curl ", "wget "
    ]

    @classmethod
    def parse(cls, raw_output: str) -> InvestigationAssessment:
        """
        Parse raw LLM response text into validated InvestigationAssessment.
        Never executes eval() or executes commands.
        """
        if not raw_output or not raw_output.strip():
            raise MalformedJSONError("LLM response was empty.")

        # Extract JSON content from markdown code fences if present
        cleaned_text = raw_output.strip()
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned_text)
        if fence_match:
            cleaned_text = fence_match.group(1).strip()

        # Parse JSON
        try:
            data = json.loads(cleaned_text)
        except json.JSONDecodeError as e:
            raise MalformedJSONError(f"Failed to parse LLM output as JSON: {e}") from e

        if not isinstance(data, dict):
            raise MalformedJSONError(f"Expected JSON object, got {type(data).__name__}.")

        # Check injection flag
        prompt_injection = data.get("prompt_injection_detected", False)
        if prompt_injection:
            return InvestigationAssessment(
                summary=str(data.get("summary", "Prompt injection flagged by model.")),
                evidence_grounding=[str(e) for e in data.get("evidence_grounding", [])],
                retrieved_references=[str(r) for r in data.get("retrieved_references", [])],
                uncertainty_or_missing_evidence=[str(u) for u in data.get("uncertainty_or_missing_evidence", [])],
                recommended_action=None,
                rationale=str(data.get("rationale", "Adversarial prompt injection detected.")),
                prompt_injection_detected=True,
            )

        # Validate recommended_action if present
        raw_action = data.get("recommended_action")
        proposal: Optional[ActionProposal] = None

        if raw_action is not None:
            if not isinstance(raw_action, dict):
                raise MalformedJSONError("recommended_action must be a JSON object or null.")

            # Validate action_type
            raw_type = raw_action.get("action_type")
            if not raw_type:
                raise MissingParameterError("recommended_action missing required field 'action_type'.")

            if raw_type not in cls.BOUNDED_ACTIONS:
                raise UnknownActionError(
                    f"Action '{raw_type}' is outside the bounded action catalogue. "
                    f"Permitted: {sorted(list(cls.BOUNDED_ACTIONS))}"
                )

            # Validate target_resource_id
            target_id = raw_action.get("target_resource_id")
            if not target_id or not str(target_id).strip():
                raise MissingParameterError("recommended_action missing required field 'target_resource_id'.")

            # Validate parameters
            parameters = raw_action.get("parameters", {})
            if not isinstance(parameters, dict):
                raise MalformedJSONError("parameters must be a key-value dictionary.")

            # Check for unexpected or suspicious parameters
            for k in parameters.keys():
                if k not in cls.ALLOWED_PARAM_KEYS:
                    raise UnexpectedParameterError(
                        f"Unexpected parameter '{k}' in proposed action. Allowed: {sorted(list(cls.ALLOWED_PARAM_KEYS))}"
                    )
                for pattern in cls.SUSPICIOUS_PARAM_PATTERNS:
                    if pattern in k.lower() or pattern in str(parameters[k]).lower():
                        raise UnexpectedParameterError(
                            f"Suspicious parameter value detected in '{k}': {parameters[k]}"
                        )

            proposal = ActionProposal(
                action_type=ActionType(raw_type),
                target_resource_id=str(target_id).strip(),
                parameters=parameters,
                rationale=str(raw_action.get("rationale", "")),
            )

        return InvestigationAssessment(
            summary=str(data.get("summary", "")),
            evidence_grounding=[str(e) for e in data.get("evidence_grounding", [])],
            retrieved_references=[str(r) for r in data.get("retrieved_references", [])],
            uncertainty_or_missing_evidence=[str(u) for u in data.get("uncertainty_or_missing_evidence", [])],
            recommended_action=proposal,
            rationale=str(data.get("rationale", "")),
            prompt_injection_detected=False,
        )
