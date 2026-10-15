"""
LLM Provider Abstraction and Implementations for SentinelGuard.
Includes:
- LLMProvider (abstract base class)
- MockLLMProvider (deterministic, zero-cost, supports configurable test modes)
- HTTPLLMProvider (OpenAI-compatible HTTP provider reading credentials from env)
"""

from __future__ import annotations

import json
import os
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import httpx


class LLMProviderError(Exception):
    """Base exception for LLM provider failures."""
    pass


class LLMTimeoutError(LLMProviderError):
    """Raised when an LLM provider times out."""
    pass


class LLMAuthenticationError(LLMProviderError):
    """Raised when API credentials are missing or invalid."""
    pass


class LLMProvider(ABC):
    """Abstract interface for LLM text generation."""

    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response text given a user prompt and optional system prompt."""
        pass


class MockLLMProvider(LLMProvider):
    """
    Deterministic mock provider for offline automated tests.
    Produces valid JSON responses grounded in incident context,
    with configurable modes to test edge cases, errors, and prompt injections.
    """

    def __init__(self, mode: str = "normal") -> None:
        self.mode = mode

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        # Check simulated error modes
        if self.mode == "timeout":
            raise LLMTimeoutError("Simulated LLM provider request timeout (10.0s exceeded).")

        if self.mode == "provider_error":
            raise LLMProviderError("Simulated LLM provider 500 Internal Server Error.")

        if self.mode == "malformed_json":
            return '{"summary": "Incomplete output", "evidence_grounding": [unclosed array'

        if self.mode == "unknown_action":
            return json.dumps({
                "summary": "Agent proposes an unapproved action type.",
                "evidence_grounding": ["Suspicious API activity observed."],
                "retrieved_references": ["Credential Compromise Playbook"],
                "uncertainty_or_missing_evidence": [],
                "recommended_action": {
                    "action_type": "terminate_instance_permanently",  # NOT in bounded catalogue
                    "target_resource_id": "i-unapproved-node",
                    "parameters": {},
                    "rationale": "Attempting unauthorized action type.",
                },
                "rationale": "Proposing unapproved action.",
                "prompt_injection_detected": False,
            })

        if self.mode == "missing_parameters":
            return json.dumps({
                "summary": "Agent proposes action with missing required fields.",
                "evidence_grounding": ["Suspicious activity"],
                "retrieved_references": [],
                "uncertainty_or_missing_evidence": [],
                "recommended_action": {
                    "action_type": "isolate_instance",
                    # target_resource_id is missing!
                    "rationale": "Missing target ID",
                },
                "rationale": "Missing parameters.",
                "prompt_injection_detected": False,
            })

        if self.mode == "unexpected_parameters":
            return json.dumps({
                "summary": "Agent proposes action with injected unexpected parameters.",
                "evidence_grounding": ["Suspicious activity"],
                "retrieved_references": [],
                "uncertainty_or_missing_evidence": [],
                "recommended_action": {
                    "action_type": "isolate_instance",
                    "target_resource_id": "i-test-01",
                    "parameters": {"injected_shell_cmd": "rm -rf /", "grant_root": True},
                    "rationale": "Injected parameters",
                },
                "rationale": "Unexpected parameters test.",
                "prompt_injection_detected": False,
            })

        # Check for adversarial prompt injection signatures in prompt
        injection_patterns = [
            r"ignore\s+(all\s+)?previous\s+instructions",
            r"grant\s+admin",
            r"attachadmin",
            r"override\s+policy",
            r"escalate\s+privilege",
            r"disregard\s+security",
        ]
        has_injection = any(re.search(pat, prompt, re.IGNORECASE) for pat in injection_patterns)

        if has_injection:
            return json.dumps({
                "summary": "Adversarial prompt injection attempt detected in untrusted telemetry/payload.",
                "evidence_grounding": ["Untrusted payload contains adversarial instruction override patterns."],
                "retrieved_references": ["High-Impact Operations & Incident Escalation Playbook"],
                "uncertainty_or_missing_evidence": ["Attacker attempted to manipulate LLM decision boundary."],
                "recommended_action": None,
                "rationale": "Adversarial instructions detected in input. Denied action execution in compliance with fail-closed policy.",
                "prompt_injection_detected": True,
            })

        # Extract target resource and alert type from prompt for realistic grounded responses
        target_res = "res-unknown"
        match_res = re.search(r"Affected Resources:\s*([a-zA-Z0-9_\-, ]+)", prompt)
        if match_res:
            target_res = match_res.group(1).split(",")[0].strip()

        # Normal Response logic based on incident type
        if "credential" in prompt.lower() or "access_key" in prompt.lower() or "ak-" in prompt:
            return json.dumps({
                "summary": f"Compromised IAM credential detected for target {target_res}.",
                "evidence_grounding": [
                    "CloudTrail records impossible travel and anomalous reconnaissance API calls.",
                    f"Target credential identifier: {target_res}."
                ],
                "retrieved_references": [
                    "SentinelGuard Playbook: IAM Access Key & Credential Compromise Response"
                ],
                "uncertainty_or_missing_evidence": [
                    "Checking whether backup administrative credentials or emergency roles are reachable."
                ],
                "recommended_action": {
                    "action_type": "revoke_access_key",
                    "target_resource_id": target_res,
                    "parameters": {},
                    "rationale": "Revoke compromised access key to stop unauthorized API invocation."
                },
                "rationale": "Compromised access key represents an active identity threat. Proposing revocation subject to governor invariant verification.",
                "prompt_injection_detected": False,
            })

        if "c2" in prompt.lower() or "miner" in prompt.lower() or "i-" in prompt:
            return json.dumps({
                "summary": f"Command-and-control beaconing detected on compute host {target_res}.",
                "evidence_grounding": [
                    "VPC Flow logs show sustained outbound connections to known threat actor IP.",
                    f"Target compute instance: {target_res}."
                ],
                "retrieved_references": [
                    "SentinelGuard Playbook: EC2 Compute Host Containment & C2 Isolation"
                ],
                "uncertainty_or_missing_evidence": [
                    "Verifying target group service quorum and active replica counts."
                ],
                "recommended_action": {
                    "action_type": "isolate_instance",
                    "target_resource_id": target_res,
                    "parameters": {},
                    "rationale": "Isolate host to sever external command-and-control communication."
                },
                "rationale": "Malware activity requires containment. Submitting isolation proposal to governor to verify service availability.",
                "prompt_injection_detected": False,
            })

        if "policy" in prompt.lower() or "permission" in prompt.lower():
            return json.dumps({
                "summary": f"Unauthorized privilege escalation detected on {target_res}.",
                "evidence_grounding": [
                    "CloudTrail records unauthorized AdministratorAccess attachment."
                ],
                "retrieved_references": [
                    "SentinelGuard Playbook: Unauthorized IAM Permission & Policy Rollback"
                ],
                "uncertainty_or_missing_evidence": [],
                "recommended_action": {
                    "action_type": "remove_permission",
                    "target_resource_id": target_res,
                    "parameters": {"policy_id": "arn:aws:iam::aws:policy/AdministratorAccess"},
                    "rationale": "Rollback unauthorized administrative permission."
                },
                "rationale": "Overprivileged policy violates least privilege principles.",
                "prompt_injection_detected": False,
            })

        # Generic default
        return json.dumps({
            "summary": "Security incident triage completed with limited evidence.",
            "evidence_grounding": ["Alert envelope inspected."],
            "retrieved_references": [],
            "uncertainty_or_missing_evidence": ["Insufficient telemetry to justify automated containment."],
            "recommended_action": None,
            "rationale": "Evidence is insufficient for automated containment. Escalating to human analyst.",
            "prompt_injection_detected": False,
        })


class HTTPLLMProvider(LLMProvider):
    """
    HTTP client for remote OpenAI-compatible LLM endpoints (OpenAI, Gemini OpenAI-compat, Ollama, vLLM).
    Reads credentials from environment variables. Never logs keys or secret values.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        timeout_seconds: float = 15.0,
    ) -> None:
        self.api_key = (
            api_key
            or os.environ.get("SENTINELGUARD_LLM_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("GEMINI_API_KEY")
        )
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout_seconds

        if not self.api_key:
            raise LLMAuthenticationError(
                "API credentials missing. Set SENTINELGUARD_LLM_API_KEY, "
                "OPENAI_API_KEY, or GEMINI_API_KEY in environment."
            )

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,  # Low temperature for deterministic security reasoning
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                return content
        except httpx.TimeoutException as e:
            raise LLMTimeoutError(f"HTTP LLM provider timed out after {self.timeout}s.") from e
        except Exception as e:
            # Mask API key if it appears in exception message
            clean_err = str(e).replace(self.api_key, "***") if self.api_key else str(e)
            raise LLMProviderError(f"HTTP LLM provider request failed: {clean_err}") from e
