"""
Incident Investigator Agent for SentinelGuard.
Coordinates RAG playbook retrieval, prompt construction, LLM generation,
and strict action parsing with fail-closed security boundaries.
"""

from __future__ import annotations

import logging
from typing import List, Optional
from sentinelguard.agent.action_parser import (
    ActionParseError,
    ActionParser,
    PromptInjectionDetectedError,
)
from sentinelguard.agent.llm_provider import LLMProvider, MockLLMProvider
from sentinelguard.agent.prompts import SYSTEM_PROMPT, format_investigation_prompt
from sentinelguard.agent.schemas import InvestigationAssessment, SecurityIncident
from sentinelguard.rag.knowledge_base import KnowledgeBase
from sentinelguard.rag.schemas import RetrievalResult

logger = logging.getLogger(__name__)


class IncidentInvestigatorAgent:
    """
    Autonomous AI Security Incident Investigator with RAG grounding.
    Proposes bounded remediation actions but never executes actions directly.
    """

    def __init__(
        self,
        knowledge_base: Optional[KnowledgeBase] = None,
        llm_provider: Optional[LLMProvider] = None,
    ) -> None:
        self.knowledge_base = knowledge_base or KnowledgeBase.create_default()
        self.llm_provider = llm_provider or MockLLMProvider()

    def investigate(
        self,
        incident: SecurityIncident,
        top_k_playbooks: int = 3,
    ) -> InvestigationAssessment:
        """
        Conduct an evidence-grounded incident investigation:
        1. Formulate search query and retrieve relevant playbooks from Knowledge Base.
        2. Format prompt with observed events, detection evidence, and retrieved guidance.
        3. Invoke LLM provider.
        4. Validate and parse response with ActionParser.
        5. Fail-closed on any parser, provider, or security failure.
        """
        # Step 1: Query Knowledge Base
        query = f"{incident.alert_type} {' '.join(incident.affected_resource_ids)}"
        if incident.observed_events:
            first_event = str(incident.observed_events[0])
            query += f" {first_event[:100]}"

        retrieved_chunks: List[RetrievalResult] = self.knowledge_base.retrieve(
            query=query, top_k=top_k_playbooks
        )

        # Step 2: Format Prompt
        prompt = format_investigation_prompt(
            incident=incident,
            retrieved_playbooks=retrieved_chunks,
        )

        # Step 3: Invoke LLM Provider
        try:
            raw_response = self.llm_provider.generate(
                prompt=prompt, system_prompt=SYSTEM_PROMPT
            )
        except Exception as e:
            logger.warning(f"LLM Provider failure during investigation of {incident.incident_id}: {e}")
            return InvestigationAssessment(
                summary=f"Investigation halted: LLM provider failure ({type(e).__name__}).",
                evidence_grounding=[],
                retrieved_references=[r.chunk.document_title for r in retrieved_chunks],
                uncertainty_or_missing_evidence=[f"Provider error: {str(e)}"],
                recommended_action=None,
                rationale="Automated triage failed due to upstream provider error. Failing closed.",
                prompt_injection_detected=False,
            )

        # Step 4: Parse & Validate Structured Output
        try:
            assessment = ActionParser.parse(raw_response)
            return assessment
        except ActionParseError as e:
            logger.warning(f"Action parser rejected model output for {incident.incident_id}: {e}")
            is_injection = isinstance(e, PromptInjectionDetectedError)
            return InvestigationAssessment(
                summary="Investigation halted: Model proposed invalid or unverified action.",
                evidence_grounding=[],
                retrieved_references=[r.chunk.document_title for r in retrieved_chunks],
                uncertainty_or_missing_evidence=[f"Parser validation error: {str(e)}"],
                recommended_action=None,
                rationale=f"Model output was rejected by security boundaries ({type(e).__name__}). Failing closed.",
                prompt_injection_detected=is_injection,
            )
