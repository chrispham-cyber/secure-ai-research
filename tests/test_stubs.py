import pytest


def test_ollama_embedder_stub_raises_on_construction():
    # PgVectorStore is a real adapter as of Slice 2 (its guards live in test_pgvector_adapter.py
    # and test_integration_pgvector.py); OllamaEmbedder remains a fail-loud stub until its slice.
    from secure_ai_research.retrieval.embeddings import OllamaEmbedder

    with pytest.raises(NotImplementedError) as exc:
        OllamaEmbedder()
    assert "ROADMAP Phase" in str(exc.value)
