"""
Embedding Provider Abstraction and Implementations for SentinelGuard RAG.
Includes:
- EmbeddingProvider (abstract base class)
- DeterministicEmbeddingProvider (offline, zero-cost, hashing-based feature vectorizer)
- APIEmbeddingProvider (configurable OpenAI-compatible embedding endpoint)
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from abc import ABC, abstractmethod
from typing import List, Optional
import httpx


def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    """Compute cosine similarity between two float vectors."""
    if len(vec1) != len(vec2) or not vec1:
        return 0.0

    dot = sum(a * b for a, b in zip(vec1, vec2))
    norm_a = math.sqrt(sum(a * a for a in vec1))
    norm_b = math.sqrt(sum(b * b for b in vec2))

    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0

    return dot / (norm_a * norm_b)


class EmbeddingProvider(ABC):
    """Abstract interface for embedding generation."""

    @abstractmethod
    def embed_text(self, text: str) -> List[float]:
        """Generate an embedding vector for a single string."""
        pass

    @abstractmethod
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embedding vectors for a batch of strings."""
        pass


class DeterministicEmbeddingProvider(EmbeddingProvider):
    """
    Offline, deterministic embedding provider using feature hashing and term frequencies.
    Requires no network, no external API keys, and no downloaded weights.
    Ideal for reproducible automated testing and deterministic demos.
    """

    def __init__(self, dimension: int = 128) -> None:
        self.dimension = dimension

    def _tokenize(self, text: str) -> List[str]:
        """Normalize and tokenize text into words and 2-grams."""
        words = re.findall(r"[a-zA-Z0-9_\-]+", text.lower())
        tokens = list(words)
        # Add bigrams for context matching
        for i in range(len(words) - 1):
            tokens.append(f"{words[i]}_{words[i+1]}")
        return tokens

    def embed_text(self, text: str) -> List[float]:
        """Convert text into a fixed-length normalized vector."""
        vec = [0.0] * self.dimension
        tokens = self._tokenize(text)

        if not tokens:
            return vec

        for token in tokens:
            # Deterministic hash bucket
            bucket = int(hashlib.sha256(token.encode("utf-8")).hexdigest(), 16) % self.dimension
            # Sign hash to reduce collisions
            sign = 1.0 if (int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16) % 2) == 0 else -1.0
            vec[bucket] += sign

        # L2 Normalize
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0.0:
            vec = [v / norm for v in vec]

        return vec

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        return [self.embed_text(t) for t in texts]


class APIEmbeddingProvider(EmbeddingProvider):
    """
    HTTP client for remote OpenAI-compatible embedding endpoints.
    Reads API credentials from environment variables. Never logs secrets.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        model: str = "text-embedding-3-small",
        timeout_seconds: float = 10.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("SENTINELGUARD_EMBEDDING_API_KEY") or os.environ.get("OPENAI_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout_seconds

        if not self.api_key:
            raise ValueError(
                "API key required for APIEmbeddingProvider. "
                "Set SENTINELGUARD_EMBEDDING_API_KEY or OPENAI_API_KEY in environment."
            )

    def embed_text(self, text: str) -> List[float]:
        res = self.embed_batch([text])
        return res[0]

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "input": texts,
            "model": self.model,
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(f"{self.base_url}/embeddings", headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                embeddings = [item["embedding"] for item in data["data"]]
                return embeddings
        except Exception as e:
            # Mask API key in any error strings
            clean_err = str(e).replace(self.api_key, "***")
            raise RuntimeError(f"Embedding API request failed: {clean_err}") from e
