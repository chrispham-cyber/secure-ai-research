import pytest


def test_adapter_stubs_raise_on_construction():
    from secure_ai_research.retrieval.embeddings import OllamaEmbedder
    from secure_ai_research.retrieval.vectorstore import PgVectorStore

    for factory in (OllamaEmbedder, PgVectorStore):
        with pytest.raises(NotImplementedError) as exc:
            factory()
        assert "ROADMAP Phase" in str(exc.value)
