"""Retrieval ports (ROADMAP Phase 2).

Protocol interfaces and value types that decouple :class:`ResearchService` from
any concrete embedding or vector-store backend. Deterministic in-memory fakes
implement these for hermetic tests; real Ollama / pgvector adapters implement the
same shape in a later slice.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ChunkRecord:
    """One stored chunk: its id, owning document, text, and embedding."""

    chunk_id: str
    document_id: str
    text: str
    embedding: list[float]


@dataclass(frozen=True)
class ChunkHit:
    """One retrieval hit: the owning document, the chunk text, and its score."""

    document_id: str
    text: str
    score: float


class Embedder(Protocol):
    """Turns chunk texts into vectors."""

    def embed(self, chunks: list[str]) -> list[list[float]]: ...


class VectorStore(Protocol):
    """Stores chunk embeddings and returns nearest neighbours within a scope."""

    def upsert(self, entries: list[ChunkRecord]) -> None: ...

    def query(
        self, embedding: list[float], *, allowed_document_ids: set[str], limit: int
    ) -> list[ChunkHit]: ...
