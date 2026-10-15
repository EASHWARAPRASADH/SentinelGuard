"""
Knowledge Base Orchestrator for SentinelGuard RAG Subsystem.
Manages loading, chunking, and indexing of security playbooks into VectorRetriever.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional
from sentinelguard.rag.chunker import DocumentChunker
from sentinelguard.rag.document_loader import DocumentLoader
from sentinelguard.rag.embeddings import DeterministicEmbeddingProvider, EmbeddingProvider
from sentinelguard.rag.retriever import VectorRetriever
from sentinelguard.rag.schemas import Document, DocumentChunk


class KnowledgeBase:
    """
    Manages the collection of security playbooks and exposes a pre-indexed VectorRetriever.
    """

    DEFAULT_PLAYBOOKS_DIR = Path(__file__).parent / "playbooks"

    def __init__(
        self,
        embedding_provider: Optional[EmbeddingProvider] = None,
        chunk_size: int = 600,
        chunk_overlap: int = 100,
    ) -> None:
        self.embedding_provider = embedding_provider or DeterministicEmbeddingProvider()
        self.chunker = DocumentChunker(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        self.retriever = VectorRetriever(embedding_provider=self.embedding_provider)
        self.documents: List[Document] = []
        self.chunks: List[DocumentChunk] = []

    def index_directory(self, playbooks_dir: Optional[str | Path] = None) -> int:
        """
        Load all playbooks from directory, chunk them, and index into the retriever.
        Returns the number of indexed chunks.
        """
        target_dir = Path(playbooks_dir) if playbooks_dir else self.DEFAULT_PLAYBOOKS_DIR
        self.documents = DocumentLoader.load_directory(target_dir)
        self.chunks = self.chunker.chunk_documents(self.documents)
        self.retriever.clear()
        self.retriever.index_chunks(self.chunks)
        return len(self.chunks)

    def retrieve(self, query: str, top_k: int = 3):
        """Query the knowledge base retriever."""
        return self.retriever.retrieve(query, top_k=top_k)

    @classmethod
    def create_default(
        cls, embedding_provider: Optional[EmbeddingProvider] = None
    ) -> KnowledgeBase:
        """Create and index the default security playbook knowledge base."""
        kb = cls(embedding_provider=embedding_provider)
        kb.index_directory()
        return kb
