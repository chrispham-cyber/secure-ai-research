"""Vector-store selection (Phase 5, Slice 2).

Maps ``Settings`` to a concrete ``VectorStore``. The default is the deterministic, dependency-free
``InMemoryVectorStore`` so the platform stays offline/hermetic unless Postgres/pgvector is
explicitly configured via ``SAIR_VECTOR_STORE=pgvector`` (which requires the ``pgvector`` extra).
``PgVectorStore`` is imported lazily, inside the pgvector branch only, so the default path and the
hermetic test suite never import ``psycopg``.
"""

from __future__ import annotations

from secure_ai_research.config import Settings
from secure_ai_research.retrieval.ports import VectorStore
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore
from secure_ai_research.transit import apply_sslmode


def make_vector_store(settings: Settings) -> VectorStore:
    """Return the store that ``settings.vector_store`` selects (default: in-memory)."""
    if settings.vector_store == "pgvector":
        from secure_ai_research.retrieval.vectorstore import PgVectorStore

        # Apply the in-transit TLS knob to the DSN (no-op unless SAIR_DB_SSLMODE is set).
        return PgVectorStore(apply_sslmode(settings.db_url, settings.db_sslmode))
    return InMemoryVectorStore()
