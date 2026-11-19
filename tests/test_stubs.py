import pytest

from secure_ai_research.evaluation import metrics

# (callable, positional args, keyword args) — each stub raises before touching
# its arguments, so dummy values that satisfy the signature's arity are enough.
# kev.load/sigma.load (Phase-2 ingestion) and the agents.functions.search_* tools
# (Phase-3 Week-9 AgentToolset) were retired from this list as they were implemented;
# metrics.score remains (Phase 4).
STUB_CALLS = [
    (metrics.score, ([], []), {}),
]

IDS = [f"{fn.__module__.split('.')[-1]}.{fn.__name__}" for fn, _, _ in STUB_CALLS]


@pytest.mark.parametrize(("fn", "args", "kwargs"), STUB_CALLS, ids=IDS)
def test_all_stubs_raise_notimplemented(fn, args, kwargs):
    with pytest.raises(NotImplementedError) as exc:
        fn(*args, **kwargs)
    assert "ROADMAP Phase" in str(exc.value)


def test_all_stubs_have_docstrings():
    for fn, _, _ in STUB_CALLS:
        assert fn.__doc__ and fn.__doc__.strip(), f"{fn.__name__} missing docstring"


def test_adapter_stubs_raise_on_construction():
    from secure_ai_research.retrieval.embeddings import OllamaEmbedder
    from secure_ai_research.retrieval.vectorstore import PgVectorStore

    for factory in (OllamaEmbedder, PgVectorStore):
        with pytest.raises(NotImplementedError) as exc:
            factory()
        assert "ROADMAP Phase" in str(exc.value)
