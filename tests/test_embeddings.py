import math

import pytest

from secure_ai_research.retrieval.embeddings import HashingEmbedder, OllamaEmbedder


def _cosine(a: list[float], b: list[float]) -> float:
    num = sum(x * y for x, y in zip(a, b, strict=True))
    da = math.sqrt(sum(x * x for x in a))
    db = math.sqrt(sum(y * y for y in b))
    return num / (da * db) if da and db else 0.0


def test_embed_is_deterministic():
    e = HashingEmbedder()
    assert e.embed(["sql injection"]) == e.embed(["sql injection"])


def test_embed_dimension_and_normalized():
    e = HashingEmbedder()
    vecs = e.embed(["sql injection in login", "another chunk of text"])
    for v in vecs:
        assert len(v) == 256
        assert math.sqrt(sum(x * x for x in v)) == pytest.approx(1.0)


def test_shared_tokens_score_higher():
    e = HashingEmbedder()
    q = e.embed(["sql injection in login"])[0]
    related = e.embed(["sql injection database"])[0]
    unrelated = e.embed(["unrelated weather forecast"])[0]
    assert _cosine(q, related) > _cosine(q, unrelated)


def test_zero_vector_for_tokenless_text():
    v = HashingEmbedder().embed(["!!! ??? ..."])[0]
    assert len(v) == 256
    assert all(x == 0.0 for x in v)


def test_ollama_embedder_is_fail_loud():
    with pytest.raises(NotImplementedError) as exc:
        OllamaEmbedder()
    assert "ROADMAP Phase" in str(exc.value)
