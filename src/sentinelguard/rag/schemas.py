"""
Schemas for the SentinelGuard RAG Subsystem.
Models documents, chunks, and retrieval results.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Document(BaseModel):
    """A loaded security playbook document."""
    id: str
    title: str
    source_path: str
    category: str = "general"
    version: str = "1.0"
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DocumentChunk(BaseModel):
    """An overlapping text chunk from a security playbook document."""
    chunk_id: str
    document_id: str
    document_title: str
    source_path: str
    category: str
    chunk_index: int
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RetrievalResult(BaseModel):
    """A retrieved chunk with relevance score and attribution."""
    chunk: DocumentChunk
    score: float
    relevance_rank: int
