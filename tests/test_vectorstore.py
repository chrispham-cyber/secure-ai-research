from secure_ai_research.retrieval.ports import ChunkRecord
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore


def _store() -> InMemoryVectorStore:
    s = InMemoryVectorStore()
    s.upsert(
        [
            ChunkRecord("A#0", "A", "alpha text", [1.0, 0.0]),
            ChunkRecord("B#0", "B", "beta text", [0.0, 1.0]),
        ]
    )
    return s


def test_query_ranks_by_cosine():
    hits = _store().query([0.9, 0.1], allowed_document_ids={"A", "B"}, limit=2)
    assert hits[0].document_id == "A"
    assert hits[0].score >= hits[1].score


def test_allowed_ids_filters_out_of_scope():
    hits = _store().query([0.9, 0.1], allowed_document_ids={"B"}, limit=2)
    assert hits and all(h.document_id == "B" for h in hits)


def test_empty_allowed_set_returns_nothing():
    assert _store().query([1.0, 0.0], allowed_document_ids=set(), limit=2) == []


def test_limit_respected():
    assert len(_store().query([1.0, 1.0], allowed_document_ids={"A", "B"}, limit=1)) == 1


def test_zero_norm_query_does_not_crash():
    hits = _store().query([0.0, 0.0], allowed_document_ids={"A", "B"}, limit=2)
    assert isinstance(hits, list)
    assert all(h.score == 0.0 for h in hits)
