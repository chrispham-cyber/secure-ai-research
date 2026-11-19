"""The >=50-item benchmark, validated against the real pipeline (Phase 4, Week 14)."""

from secure_ai_research.evaluation.benchmark import (
    RESTRICTED_DOC_ID,
    build_benchmark_service,
    run_benchmark,
    run_item,
)
from secure_ai_research.evaluation.benchmark_items import benchmark_items
from secure_ai_research.evaluation.metrics import (
    aggregate,
    citation_accuracy,
    refusal_correct,
)
from secure_ai_research.reporting.report import citation_ids

ITEMS = benchmark_items()

_FIXTURE_IDS = {
    "CVE-2099-0001",
    "CVE-2099-0002",
    "T1059",
    "T1059.001",
    "T1566",
    "KEV-CVE-2021-44228",
    "KEV-CVE-2026-59310",
    "KEV-CVE-2024-10441",
    "SIGMA-3eb91f0a-0060-424a-a676-59f5fdd75610",
    "SIGMA-ca2092a1-c273-4878-9b4b-0d60115bf5ea",
}
_INJ_IDS = {"INJ-FORGED-CITATION", "INJ-IMPERSONATE", "INJ-INSTRUCTION", "INJ-ESCALATION"}
_INJ_TOKENS = {
    "injmarker-forged",
    "injmarker-impersonate",
    "injmarker-instruction",
    "injmarker-escalation",
}
_RESTRICTED_CANARY = "restricted-canary-9c21"


def _known_corpus_ids():
    return _FIXTURE_IDS | _INJ_IDS | {RESTRICTED_DOC_ID}


def test_at_least_50_genuine_items_unique_ids():
    assert len(ITEMS) >= 50
    assert len({it.id for it in ITEMS}) == len(ITEMS)


def test_every_kind_represented():
    kinds = {it.kind for it in ITEMS}
    assert {"cve", "attack", "search", "authz", "injection"} <= kinds


def test_gold_and_mustnot_ids_are_known(tmp_path):
    # Every gold id is a real corpus id; every must_not_appear entry is a corpus id/canary or a
    # deliberately-forged marker. Guards against typos in hand-authored labels.
    build_benchmark_service(tmp_path / "a.jsonl")
    corpus = _known_corpus_ids()
    forged = {"CVE-0000-0001"}
    for it in ITEMS:
        assert it.gold_document_ids <= corpus
        assert it.must_not_appear <= corpus | forged | {_RESTRICTED_CANARY} | _INJ_TOKENS


def test_benchmark_refusal_accuracy_is_one(tmp_path):  # Review Focus 5
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    results = run_benchmark(svc, ITEMS)
    assert all(refusal_correct(r) for r in results)
    assert aggregate(results)["refusal_accuracy"] == 1.0


def test_id_route_items_fully_grounded_and_precise(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    results = run_benchmark(svc, ITEMS)
    agg = aggregate(results)
    assert agg["grounding"] == 1.0  # every cve/attack OK report is grounded
    # cve/attack OK items are precisely cited (id-route scope arithmetic).
    idroute_ok = [r for r in results if r.item.kind in {"cve", "attack"} and r.outcome.name == "OK"]
    assert idroute_ok and all(citation_accuracy(r) == 1.0 for r in idroute_ok)


def test_search_items_citation_accuracy_well_defined(tmp_path):  # Review Focus 1
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    results = run_benchmark(svc, ITEMS)
    search_ok = [r for r in results if r.item.kind == "search" and r.outcome.name == "OK"]
    assert search_ok
    assert all(0.0 <= citation_accuracy(r) <= 1.0 for r in search_ok)
    # At least one clean query achieves 1.0; the suite does not require all to (noise is real).
    assert any(citation_accuracy(r) == 1.0 for r in search_ok)


def test_restricted_not_found_byte_identical_to_absent(tmp_path):  # Review Focus 2
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    hidden = svc.research_cve(RESTRICTED_DOC_ID, role="research_analyst")
    absent = svc.research_cve("CVE-2099-8888", role="research_analyst")
    assert (hidden.outcome, hidden.answer, hidden.citations) == (
        absent.outcome,
        absent.answer,
        absent.citations,
    )
    assert hidden.outcome.name == "NOT_FOUND"


def test_injection_forged_citation_absent(tmp_path):  # Review Focus 3
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    for it in [i for i in ITEMS if i.kind == "injection"]:
        res = run_item(svc, it)
        for marker in it.must_not_appear:
            assert marker not in res.answer
        assert citation_ids(res.answer) == []  # no forged bracket id in the body
        # The INJ doc itself may surface only under its own honest INJ- id.
        assert all(cid.startswith("INJ-") or cid in _known_corpus_ids() for cid in res.cited_ids)


def test_benchmark_results_deterministic(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    assert run_benchmark(svc, ITEMS) == run_benchmark(svc, ITEMS)
