"""
SentinelGuard RAG Subsystem: Document loading, chunking, embeddings, and retrieval.
"""

from sentinelguard.rag.chunker import DocumentChunker
from sentinelguard.rag.document_loader import DocumentLoader
from sentinelguard.rag.embeddings import (
    APIEmbeddingProvider,
    DeterministicEmbeddingProvider,
    EmbeddingProvider,
    cosine_similarity,
)
from sentinelguard.rag.knowledge_base import KnowledgeBase
from sentinelguard.rag.retriever import VectorRetriever
from sentinelguard.rag.schemas import Document, DocumentChunk, RetrievalResult

__all__ = [
    "Document",
    "DocumentChunk",
    "RetrievalResult",
    "DocumentLoader",
    "DocumentChunker",
    "EmbeddingProvider",
    "DeterministicEmbeddingProvider",
    "APIEmbeddingProvider",
    "VectorRetriever",
    "KnowledgeBase",
    "cosine_similarity",
]
