"""Vector store (Postgres + pgvector) — **stub** (ROADMAP Phase 2).

Persist chunks, their embeddings, and their source integrity hashes, and return
the nearest neighbours for a query — but only among documents the caller's role
is authorized to see.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secure_ai_research.ingestion.schema import ResearchDocument


def upsert(documents: list[ResearchDocument]) -> None:
    """Insert or update documents and their embeddings in pgvector (not yet implemented)."""
    raise NotImplementedError(
        "Vector store upsert — ROADMAP Phase 2 (weeks 5-8): persist chunks and "
        "embeddings in Postgres/pgvector with their integrity hashes"
    )


def retrieve(query: str, *, role: str) -> list[ResearchDocument]:
    """Return documents relevant to ``query`` that ``role`` may access (not yet implemented).

    Authorization is applied **before** retrieval (see
    :func:`secure_ai_research.retrieval.authz.authorize`), never after generation.
    """
    raise NotImplementedError(
        "Retrieval — ROADMAP Phase 2 (weeks 5-8): authorization is applied before "
        "retrieval, never after generation"
    )
