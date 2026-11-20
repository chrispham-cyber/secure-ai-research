"""Vector store (ROADMAP Phase 2).

``InMemoryVectorStore`` is a deterministic, dependency-free fake used for hermetic
tests and the default app wiring this slice. It ranks stored chunks by cosine
similarity **only within the caller's authorized document scope** — the scope is a
query parameter, so authorization gates retrieval by construction, never as a
post-filter. ``PgVectorStore`` is the real Postgres/pgvector adapter wired in a
later slice; it fails loud until then.
"""

from __future__ import annotations

import math

from secure_ai_research.retrieval.ports import ChunkHit, ChunkRecord


def _cosine(a: list[float], b: list[float]) -> float:
    num = sum(x * y for x, y in zip(a, b, strict=False))
    da = math.sqrt(sum(x * x for x in a))
    db = math.sqrt(sum(y * y for y in b))
    return num / (da * db) if da and db else 0.0


class InMemoryVectorStore:
    """In-memory cosine vector store (implements ``VectorStore``)."""

    def __init__(self) -> None:
        self._records: list[ChunkRecord] = []

    def upsert(self, entries: list[ChunkRecord]) -> None:
        self._records.extend(entries)

    def query(
        self, embedding: list[float], *, allowed_document_ids: set[str], limit: int
    ) -> list[ChunkHit]:
        scored = [
            ChunkHit(r.document_id, r.text, _cosine(embedding, r.embedding))
            for r in self._records
            if r.document_id in allowed_document_ids
        ]
        scored.sort(key=lambda h: h.score, reverse=True)
        return scored[:limit]


class PgVectorStore:
    """Postgres/pgvector-backed store (implements ``VectorStore``) — real adapter next task.

    The signatures are fixed here — a ``dsn`` constructor plus the ``VectorStore`` methods — so
    the ``make_vector_store`` factory type-checks against this class now; the bodies stay
    fail-loud until Slice 2 Task 4 wires the real psycopg/pgvector adapter. ``dsn`` defaults to
    ``""`` so the stub-construction test keeps calling ``PgVectorStore()``.
    """

    def __init__(self, dsn: str = "") -> None:
        self._dsn = dsn
        raise NotImplementedError(
            "Vector store via Postgres/pgvector — ROADMAP Phase 2 (weeks 5-8): Slice 2 Task 4 "
            "wires the real adapter (scope filter as a SQL predicate)"
        )

    def upsert(self, entries: list[ChunkRecord]) -> None:
        raise NotImplementedError

    def query(
        self, embedding: list[float], *, allowed_document_ids: set[str], limit: int
    ) -> list[ChunkHit]:
        raise NotImplementedError
