"""
Document Loader for SentinelGuard RAG Subsystem.
Loads locally stored Markdown and text security playbooks,
validates file integrity, extracts metadata, and treats content as untrusted.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from sentinelguard.rag.schemas import Document


class DocumentLoadError(Exception):
    """Raised when a document cannot be loaded or is invalid."""
    pass


class DocumentLoader:
    """
    Safely loads security playbook documents from disk.
    Enforces format validation, metadata extraction, and safe text decoding.
    """

    ALLOWED_EXTENSIONS = {".md", ".markdown", ".txt"}

    @classmethod
    def load_file(cls, file_path: str | Path) -> Document:
        """
        Load a single document from path, validating format and extracting metadata.
        """
        path = Path(file_path).resolve()

        if not path.exists():
            raise DocumentLoadError(f"File not found: {path}")

        if not path.is_file():
            raise DocumentLoadError(f"Path is not a regular file: {path}")

        if path.suffix.lower() not in cls.ALLOWED_EXTENSIONS:
            raise DocumentLoadError(
                f"Unsupported file extension '{path.suffix}'. Allowed: {cls.ALLOWED_EXTENSIONS}"
            )

        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as e:
            raise DocumentLoadError(f"Failed to decode file as UTF-8: {path} ({e})")
        except Exception as e:
            raise DocumentLoadError(f"Error reading file {path}: {e}")

        if not content.strip():
            raise DocumentLoadError(f"Document is empty: {path}")

        # Extract title and metadata from content or filename
        doc_id = path.stem.lower().replace(" ", "_")
        title = cls._extract_title(content, fallback=path.stem)
        category = cls._extract_category(content, path)
        version = cls._extract_version(content)

        return Document(
            id=doc_id,
            title=title,
            source_path=str(path),
            category=category,
            version=version,
            content=content,
            metadata={
                "file_size_bytes": len(content.encode("utf-8")),
                "filename": path.name,
            },
        )

    @classmethod
    def load_directory(
        cls, directory_path: str | Path, recursive: bool = True
    ) -> List[Document]:
        """
        Load all permitted documents from a directory.
        Malformed documents are recorded and skipped without crashing the loader.
        """
        dir_path = Path(directory_path).resolve()
        if not dir_path.exists() or not dir_path.is_dir():
            raise DocumentLoadError(f"Invalid directory path: {dir_path}")

        documents: List[Document] = []
        pattern = "**/*" if recursive else "*"

        for file_path in dir_path.glob(pattern):
            if file_path.is_file() and file_path.suffix.lower() in cls.ALLOWED_EXTENSIONS:
                try:
                    doc = cls.load_file(file_path)
                    documents.append(doc)
                except DocumentLoadError:
                    # Skip malformed/empty files safely
                    continue

        return documents

    @staticmethod
    def _extract_title(content: str, fallback: str) -> str:
        """Extract first markdown heading or use fallback."""
        match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
        if match:
            return match.group(1).strip()
        return fallback.replace("_", " ").title()

    @staticmethod
    def _extract_category(content: str, path: Path) -> str:
        """Extract category from metadata comments or directory/filename hints."""
        match = re.search(r"<!--\s*category:\s*([a-zA-Z0-9_\-]+)\s*-->", content)
        if match:
            return match.group(1).strip().lower()

        name = path.stem.lower()
        if "credential" in name or "iam" in name:
            return "identity_and_access"
        if "instance" in name or "ec2" in name:
            return "compute_isolation"
        if "telemetry" in name or "cloudtrail" in name or "logging" in name:
            return "telemetry_and_audit"
        if "escalation" in name or "approval" in name:
            return "incident_escalation"
        return "general"

    @staticmethod
    def _extract_version(content: str) -> str:
        """Extract version from metadata comments or default to 1.0."""
        match = re.search(r"<!--\s*version:\s*([0-9\.]+)\s*-->", content)
        if match:
            return match.group(1).strip()
        return "1.0"
