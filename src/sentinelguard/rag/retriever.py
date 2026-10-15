"""
Vector Retriever for SentinelGuard RAG Subsystem.
Stores document chunk embeddings and executes cosine-similarity search.
"""

from __future__ import annotations

from typing import List, Optional, Tuple
from sentinelguard.rag.embeddings import (
    DeterministicEmbeddingProvider,
    EmbeddingProvider,
    cosine_similarity,
)
from sentinelguard.rag.schemas import DocumentChunk, RetrievalResult


class VectorRetriever:
    """
    In-memory vector store and retrieval engine for security playbook chunks.
    """

    def __init__(self, embedding_provider: Optional[EmbeddingProvider] = None) -> None:
        self.embedding_provider = embedding_provider or DeterministicEmbeddingProvider()
        self.chunks: List[DocumentChunk] = []
        self.vectors: List[List[float]] = []

    def index_chunks(self, chunks: List[DocumentChunk]) -> int:
        """
        Embed and index a list of document chunks.
        Returns the total number of chunks currently indexed.
        """
        if not chunks:
            return len(self.chunks)

        texts = [c.content for c in chunks]
        new_vectors = self.embedding_provider.embed_batch(texts)

        self.chunks.extend(chunks)
        self.vectors.extend(new_vectors)
        return len(self.chunks)

    def retrieve(
        self, query: str, top_k: int = 3, min_score: float = 0.05
    ) -> List[RetrievalResult]:
        """
        Retrieve the most relevant document chunks for a security incident query.
        """
        if not self.chunks or not query.strip():
            return []

        query_vec = self.embedding_provider.embed_text(query)
        scored: List[Tuple[float, DocumentChunk]] = []

        for vec, chunk in zip(self.vectors, self.chunks):
            score = cosine_similarity(query_vec, vec)
            if score >= min_score:
                scored.append((score, chunk))

        # Sort descending by score
        scored.sort(key=lambda x: x[0], reverse=True)

        results: List[RetrievalResult] = []
        for rank, (score, chunk) in enumerate(scored[:top_k], start=1):
            results.append(
                RetrievalResult(
                    chunk=chunk,
                    score=round(score, 4),
                    relevance_rank=rank,
                )
            )

        return results

    def clear(self) -> None:
        """Clear all indexed chunks and embeddings."""
        self.chunks.clear()
        self.vectors.clear()

    @property
    def total_chunks(self) -> int:
        return len(self.chunks)
