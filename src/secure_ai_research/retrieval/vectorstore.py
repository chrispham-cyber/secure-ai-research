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
from typing import Any

from secure_ai_research.retrieval.embeddings import DIM as _EMBED_DIM
from secure_ai_research.retrieval.ports import ChunkHit, ChunkRecord, VectorStoreError

# Connect timeout for every short-lived PgVectorStore connection. A store outage must surface
# as a bounded VectorStoreError (→ FETCH_ERROR → 503), never an unbounded request hang.
_CONNECT_TIMEOUT = 10


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
    """Postgres/pgvector-backed vector store (implements ``VectorStore``).

    Opt-in backend selected by ``SAIR_VECTOR_STORE=pgvector``. ``psycopg`` and the ``pgvector``
    adapter are imported lazily (inside ``__init__``), so importing this module never pulls them
    in and the default in-memory path stays dependency-free. A missing ``pgvector`` extra, or any
    connection/query fault, is raised as a ``VectorStoreError`` carrying only an exception-type
    tag — never row data or a backend message — so the service fails closed (→ FETCH_ERROR → 503)
    and no backend detail leaks into the audit trail.

    Authorization is enforced **in SQL**: ``query`` filters by ``document_id = ANY(scope)`` as a
    predicate, so a caller never sees a chunk outside their scope — the same by-construction gate
    as ``InMemoryVectorStore``. Ranking is exact nearest-neighbour by cosine distance (no ANN
    index), so results match the in-memory store's ordering under the same deterministic embedder.
    Each operation uses its own short-lived connection, so the adapter is safe under concurrency.
    """

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._psycopg, self._register_vector, self._vector_cls = self._load_driver()
        self._ensure_schema()

    @staticmethod
    def _load_driver() -> tuple[Any, Any, Any]:
        """Import psycopg + the pgvector adapter + Vector type, or fail loud with remediation."""
        try:
            import psycopg
            from pgvector import Vector
            from pgvector.psycopg import register_vector
        except ImportError as exc:
            raise VectorStoreError(
                "pgvector extra not installed: pip install '.[pgvector]'"
            ) from exc
        return psycopg, register_vector, Vector

    def _connect(self, *, register: bool) -> Any:
        """Open a short-lived connection, mapping any failure to VectorStoreError.

        ``register`` adds the pgvector type adapter; it must be False before the ``vector``
        extension exists (the first connection, in ``_ensure_schema``), True afterwards.
        """
        try:
            conn = self._psycopg.connect(self._dsn, connect_timeout=_CONNECT_TIMEOUT)
        except Exception as exc:
            raise VectorStoreError(f"vector store unavailable ({type(exc).__name__})") from exc
        if register:
            self._register_vector(conn)
        return conn

    def _ensure_schema(self) -> None:
        try:
            with self._connect(register=False) as conn:
                conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS sair_chunks ("
                    "chunk_id text primary key, "
                    "document_id text not null, "
                    "text text not null, "
                    # dimension pinned to the deterministic embedder's DIM (imported) so the
                    # column and the vectors can never drift apart.
                    f"embedding vector({_EMBED_DIM}) not null)"
                )
                conn.commit()
        except VectorStoreError:
            raise
        except Exception as exc:
            raise VectorStoreError(f"schema init failed ({type(exc).__name__})") from exc

    def upsert(self, entries: list[ChunkRecord]) -> None:
        if not entries:
            return
        try:
            with self._connect(register=True) as conn:
                with conn.cursor() as cur:
                    cur.executemany(
                        "INSERT INTO sair_chunks (chunk_id, document_id, text, embedding) "
                        "VALUES (%s, %s, %s, %s) "
                        "ON CONFLICT (chunk_id) DO UPDATE SET "
                        "document_id = EXCLUDED.document_id, "
                        "text = EXCLUDED.text, "
                        "embedding = EXCLUDED.embedding",
                        [
                            (e.chunk_id, e.document_id, e.text, self._vector_cls(e.embedding))
                            for e in entries
                        ],
                    )
                conn.commit()
        except VectorStoreError:
            raise
        except Exception as exc:
            raise VectorStoreError(f"upsert failed ({type(exc).__name__})") from exc

    def query(
        self, embedding: list[float], *, allowed_document_ids: set[str], limit: int
    ) -> list[ChunkHit]:
        scope = list(allowed_document_ids)
        try:
            with self._connect(register=True) as conn:
                rows = conn.execute(
                    # score = cosine similarity = 1 - cosine distance (<=>); ORDER BY distance ASC
                    # is similarity DESC. Scope is a SQL predicate, never a post-filter.
                    "SELECT document_id, text, 1 - (embedding <=> %s) AS score "
                    "FROM sair_chunks "
                    "WHERE document_id = ANY(%s) "
                    "ORDER BY embedding <=> %s "
                    "LIMIT %s",
                    (self._vector_cls(embedding), scope, self._vector_cls(embedding), limit),
                ).fetchall()
        except VectorStoreError:
            raise
        except Exception as exc:
            raise VectorStoreError(f"query failed ({type(exc).__name__})") from exc
        return [ChunkHit(document_id=r[0], text=r[1], score=float(r[2])) for r in rows]
