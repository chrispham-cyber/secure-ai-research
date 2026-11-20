"""Integration tests for the real PgVectorStore adapter (Phase 5, Slice 2, Task 4).

Marked ``integration`` → excluded from the default hermetic run and from CI; run with
``-m integration`` against a live Postgres/pgvector (``docker compose up -d db``) with the
``pgvector`` extra installed (``pip install -e '.[pgvector]'``). They SKIP cleanly when psycopg,
the pgvector extra, or a reachable Postgres is absent.

IMPORTANT: ``psycopg`` is imported only INSIDE functions, never at module top — deselected files
are still collected (imported), so a top-level ``import psycopg`` would break the hermetic run.
"""

from __future__ import annotations

import pytest

from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.ports import ChunkRecord, VectorStoreError
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore, PgVectorStore

pytestmark = pytest.mark.integration

_DSN = "postgresql://sair:sair@localhost:5432/sair"
_EMB = HashingEmbedder()

# Four clearly-distinct documents so the ranked order has no score ties (float32 storage in
# pgvector vs float64 in the in-memory store must not reorder them).
_TEXTS = {
    "DOC-A": "log4j remote code execution via jndi ldap lookup exploit",
    "DOC-B": "local privilege escalation linux kernel use after free",
    "DOC-C": "sql injection in a web application database query parameter",
    "DOC-D": "phishing email social engineering stolen credential reuse",
}
_QUERY = _EMB.embed(["remote code execution exploit through a jndi ldap lookup"])[0]


def _records() -> list[ChunkRecord]:
    return [
        ChunkRecord(
            chunk_id=f"{doc}:0", document_id=doc, text=text, embedding=_EMB.embed([text])[0]
        )
        for doc, text in _TEXTS.items()
    ]


def _require_pg() -> None:
    pytest.importorskip("psycopg")
    pytest.importorskip("pgvector")
    import psycopg

    try:
        with psycopg.connect(_DSN, connect_timeout=3):
            pass
    except Exception as exc:  # noqa: BLE001 - any connect failure means "pg not available here"
        pytest.skip(f"Postgres not reachable: {type(exc).__name__}")


@pytest.fixture
def pg() -> PgVectorStore:
    _require_pg()
    store = PgVectorStore(_DSN)  # __init__ ensures the extension + table exist
    import psycopg

    with psycopg.connect(_DSN, connect_timeout=5) as conn:
        conn.execute("TRUNCATE sair_chunks")
        conn.commit()
    return store


def _row_count() -> int:
    import psycopg

    with psycopg.connect(_DSN, connect_timeout=5) as conn:
        return conn.execute("SELECT count(*) FROM sair_chunks").fetchone()[0]


def test_parity_with_in_memory(pg: PgVectorStore) -> None:
    recs = _records()
    mem = InMemoryVectorStore()
    mem.upsert(recs)
    pg.upsert(recs)
    scope = {r.document_id for r in recs}
    mem_hits = mem.query(_QUERY, allowed_document_ids=scope, limit=5)
    pg_hits = pg.query(_QUERY, allowed_document_ids=scope, limit=5)
    # Exact-NN parity: identical ranked document-id order via the same deterministic embedder.
    assert [h.document_id for h in pg_hits] == [h.document_id for h in mem_hits]
    for p, m in zip(pg_hits, mem_hits, strict=True):
        assert p.score == pytest.approx(m.score, abs=1e-5)  # float32 storage tolerance


def test_scope_is_a_sql_predicate(pg: PgVectorStore) -> None:
    recs = _records()
    pg.upsert(recs)
    # DOC-A is the top hit for _QUERY; excluding it from scope must yield no hit from it.
    hits = pg.query(_QUERY, allowed_document_ids={"DOC-B", "DOC-C", "DOC-D"}, limit=5)
    assert all(h.document_id != "DOC-A" for h in hits)
    assert {h.document_id for h in hits} <= {"DOC-B", "DOC-C", "DOC-D"}


def test_upsert_is_idempotent(pg: PgVectorStore) -> None:
    recs = _records()
    pg.upsert(recs)
    pg.upsert(recs)  # ON CONFLICT upsert, not a second insert
    assert _row_count() == len(recs)


def test_query_equal_to_chunk_scores_near_one(pg: PgVectorStore) -> None:
    recs = _records()
    pg.upsert(recs)
    a = next(r for r in recs if r.document_id == "DOC-A")
    hits = pg.query(a.embedding, allowed_document_ids={"DOC-A"}, limit=1)
    # Cosine orientation guard: a chunk queried with its own unit embedding scores ~1.0.
    assert hits
    assert hits[0].score == pytest.approx(1.0, abs=1e-5)


def test_bad_dsn_raises_vector_store_error() -> None:
    _require_pg()  # psycopg must be importable; the DSN below is deliberately unreachable
    with pytest.raises(VectorStoreError):
        PgVectorStore("postgresql://nope:nope@127.0.0.1:1/none").query(
            [0.0] * 256, allowed_document_ids={"x"}, limit=5
        )
