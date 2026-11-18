import pytest

from secure_ai_research.agents import functions
from secure_ai_research.evaluation import metrics
from secure_ai_research.ingestion import attack, kev, nvd, sigma
from secure_ai_research.reporting import report
from secure_ai_research.retrieval import authz, chunking, embeddings, vectorstore

# (callable, positional args, keyword args) — each stub raises before touching
# its arguments, so dummy values that satisfy the signature's arity are enough.
STUB_CALLS = [
    (nvd.load, (b"",), {}),
    (kev.load, (b"",), {}),
    (attack.load, (b"",), {}),
    (sigma.load, (b"",), {}),
    (chunking.chunk, ("",), {}),
    (embeddings.embed, ([],), {}),
    (vectorstore.upsert, ([],), {}),
    (vectorstore.retrieve, ("q",), {"role": "analyst"}),
    (authz.authorize, ("analyst", None), {}),
    (metrics.score, ([], []), {}),
    (report.build_report, (None,), {}),
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
