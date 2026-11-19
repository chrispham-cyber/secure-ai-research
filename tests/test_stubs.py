import pytest

from secure_ai_research.agents import functions
from secure_ai_research.evaluation import metrics
from secure_ai_research.ingestion import attack, kev, sigma

# (callable, positional args, keyword args) — each stub raises before touching
# its arguments, so dummy values that satisfy the signature's arity are enough.
STUB_CALLS = [
    (kev.load, (b"",), {}),
    (attack.load, (b"",), {}),
    (sigma.load, (b"",), {}),
    (metrics.score, ([], []), {}),
    (functions.search_cve, ("CVE-2026-0001",), {}),
    (functions.search_attack, ("T1059",), {}),
    (functions.search_research, ("ransomware",), {}),
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
