"""
Document Chunker for SentinelGuard RAG Subsystem.
Splits playbook documents into configurable overlapping chunks,
preserving source attribution and section structure.
"""

from __future__ import annotations

import re
from typing import List
from sentinelguard.rag.schemas import Document, DocumentChunk


class DocumentChunker:
    """
    Splits documents into overlapping chunks with source metadata preservation.
    """

    def __init__(
        self,
        chunk_size: int = 600,
        chunk_overlap: int = 100,
        min_chunk_size: int = 50,
    ) -> None:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if chunk_overlap < 0 or chunk_overlap >= chunk_size:
            raise ValueError("chunk_overlap must be non-negative and smaller than chunk_size")

        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.min_chunk_size = min_chunk_size

    def chunk_document(self, document: Document) -> List[DocumentChunk]:
        """
        Split a Document into an ordered list of DocumentChunk objects.
        """
        raw_text = document.content.strip()
        if not raw_text:
            return []

        # Split into natural paragraphs / sections first
        paragraphs = [p.strip() for p in re.split(r"\n\s*\n", raw_text) if p.strip()]

        # Combine paragraphs into chunks up to chunk_size with overlap
        chunks: List[str] = []
        current_chunk = ""

        for para in paragraphs:
            if not current_chunk:
                current_chunk = para
            elif len(current_chunk) + len(para) + 2 <= self.chunk_size:
                current_chunk += "\n\n" + para
            else:
                chunks.append(current_chunk)
                # Apply overlap by carrying over suffix of previous chunk
                overlap_text = current_chunk[-self.chunk_overlap:] if len(current_chunk) > self.chunk_overlap else current_chunk
                current_chunk = overlap_text + "\n\n" + para

        if current_chunk and current_chunk not in chunks:
            chunks.append(current_chunk)

        # Fallback if text has no paragraphs (single monolithic block)
        if not chunks:
            start = 0
            while start < len(raw_text):
                end = min(start + self.chunk_size, len(raw_text))
                chunk_slice = raw_text[start:end].strip()
                if len(chunk_slice) >= self.min_chunk_size:
                    chunks.append(chunk_slice)
                start += self.chunk_size - self.chunk_overlap

        # Build DocumentChunk models with metadata
        document_chunks: List[DocumentChunk] = []
        for idx, text in enumerate(chunks):
            chunk_id = f"{document.id}_chunk_{idx:03d}"
            document_chunks.append(
                DocumentChunk(
                    chunk_id=chunk_id,
                    document_id=document.id,
                    document_title=document.title,
                    source_path=document.source_path,
                    category=document.category,
                    chunk_index=idx,
                    content=text,
                    metadata={
                        **document.metadata,
                        "char_length": len(text),
                    },
                )
            )

        return document_chunks

    def chunk_documents(self, documents: List[Document]) -> List[DocumentChunk]:
        """Chunk a list of documents."""
        all_chunks: List[DocumentChunk] = []
        for doc in documents:
            all_chunks.extend(self.chunk_document(doc))
        return all_chunks
