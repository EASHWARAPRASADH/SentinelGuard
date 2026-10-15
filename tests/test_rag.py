"""
Automated Unit Tests for SentinelGuard RAG Subsystem.
Tests:
- Correct retrieval for credential-compromise incident.
- Correct retrieval for telemetry-continuity incident.
- Missing or empty knowledge base.
- Malformed documents handling.
- Source metadata preservation.
"""

from pathlib import Path
import pytest

from sentinelguard.rag.chunker import DocumentChunker
from sentinelguard.rag.document_loader import DocumentLoader, DocumentLoadError
from sentinelguard.rag.embeddings import DeterministicEmbeddingProvider
from sentinelguard.rag.knowledge_base import KnowledgeBase
from sentinelguard.rag.retriever import VectorRetriever
from sentinelguard.rag.schemas import Document


def test_rag_retrieval_credential_compromise():
    """Verify top hit for credential compromise query is the credential playbook."""
    kb = KnowledgeBase.create_default()
    assert kb.retriever.total_chunks > 0

    results = kb.retrieve(query="compromised IAM access key anomalous API calling pattern", top_k=2)
    assert len(results) > 0
    top_doc = results[0].chunk.document_title
    assert "Credential Compromise" in top_doc or "IAM" in top_doc
    assert results[0].score > 0.05


def test_rag_retrieval_telemetry_continuity():
    """Verify top hit for telemetry query is telemetry or logging protection."""
    kb = KnowledgeBase.create_default()
    results = kb.retrieve(query="CloudTrail audit logging bucket severed KMS key", top_k=3)
    assert len(results) > 0
    titles = [r.chunk.document_title for r in results]
    assert any("Telemetry" in t or "Policy Rollback" in t for t in titles)


def test_rag_empty_or_missing_knowledge_base():
    """Verify VectorRetriever handles empty chunks gracefully without crashing."""
    retriever = VectorRetriever()
    results = retriever.retrieve("any query here", top_k=5)
    assert results == []

    # Query with empty text
    retriever.index_chunks([])
    assert retriever.retrieve("", top_k=3) == []


def test_rag_malformed_document_handling(tmp_path: Path):
    """Verify DocumentLoader rejects non-existent, empty, or unsupported files."""
    # 1. Non-existent file
    with pytest.raises(DocumentLoadError, match="File not found"):
        DocumentLoader.load_file(tmp_path / "does_not_exist.md")

    # 2. Unsupported extension
    invalid_ext = tmp_path / "script.py"
    invalid_ext.write_text("print('hello')", encoding="utf-8")
    with pytest.raises(DocumentLoadError, match="Unsupported file extension"):
        DocumentLoader.load_file(invalid_ext)

    # 3. Empty document
    empty_file = tmp_path / "empty.md"
    empty_file.write_text("   \n   ", encoding="utf-8")
    with pytest.raises(DocumentLoadError, match="Document is empty"):
        DocumentLoader.load_file(empty_file)

    # 4. Directory loading safely skips malformed files without throwing
    valid_file = tmp_path / "valid.md"
    valid_file.write_text("# Valid Playbook\nThis is a valid test document.", encoding="utf-8")
    docs = DocumentLoader.load_directory(tmp_path)
    assert len(docs) == 1
    assert docs[0].title == "Valid Playbook"


def test_rag_source_metadata_preservation():
    """Verify that chunking preserves document IDs, categories, and source paths."""
    doc = Document(
        id="test_playbook_doc",
        title="Test Security Playbook",
        source_path="/etc/security/playbooks/test.md",
        category="identity_and_access",
        version="2.1",
        content="## Section 1\nFirst paragraph of incident guidance.\n\n## Section 2\nSecond paragraph of containment steps.",
        metadata={"author": "SecOps Team"},
    )
    chunker = DocumentChunker(chunk_size=100, chunk_overlap=20)
    chunks = chunker.chunk_document(doc)

    assert len(chunks) >= 2
    for chunk in chunks:
        assert chunk.document_id == "test_playbook_doc"
        assert chunk.document_title == "Test Security Playbook"
        assert chunk.source_path == "/etc/security/playbooks/test.md"
        assert chunk.category == "identity_and_access"
        assert chunk.metadata["author"] == "SecOps Team"
        assert chunk.metadata["char_length"] == len(chunk.content)
