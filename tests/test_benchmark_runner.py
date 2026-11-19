"""Benchmark runner: kind dispatch + per-kind EvalResult derivation (Phase 4, Week 14)."""

import pytest

from secure_ai_research.evaluation.benchmark import (
    RESTRICTED_DOC_ID,
    build_benchmark_service,
    run_benchmark,
    run_item,
)
from secure_ai_research.evaluation.metrics import citation_accuracy, grounding
from secure_ai_research.evaluation.records import EvalItem
from secure_ai_research.research_service import Outcome


@pytest.fixture
def service(tmp_path):
    return build_benchmark_service(tmp_path / "a.jsonl")


def test_run_item_cve_ok_maps_fields(service):
    item = EvalItem(
        id="t",
        kind="cve",
        query="CVE-2099-0001",
        role="research_analyst",
        expected_outcome=Outcome.OK,
        gold_document_ids=frozenset({"CVE-2099-0001"}),
    )
    res = run_item(service, item)
    assert res.outcome is Outcome.OK
    assert res.retrieved_ids == ("CVE-2099-0001",)
    assert res.cited_ids == ("CVE-2099-0001",)  # body citation
    assert grounding(res) == 1.0 and citation_accuracy(res) == 1.0


def test_run_item_authz_cve_query_uses_id_route(service):  # Review Focus 4
    # A RESTRICTED id as research_analyst must be NOT_FOUND via the id-route, not an OK search.
    item = EvalItem(
        id="t",
        kind="authz",
        query=RESTRICTED_DOC_ID,
        role="research_analyst",
        expected_outcome=Outcome.NOT_FOUND,
        gold_document_ids=frozenset(),
    )
    res = run_item(service, item)
    assert res.outcome is Outcome.NOT_FOUND and res.answer == "" and res.cited_ids == ()


def test_run_item_search_cited_ids_are_ranked_ids(service):  # Review Focus 4
    item = EvalItem(
        id="t",
        kind="search",
        query="log4j",
        role="research_analyst",
        expected_outcome=Outcome.OK,
        gold_document_ids=frozenset({"KEV-CVE-2021-44228"}),
    )
    res = run_item(service, item)
    assert res.outcome is Outcome.OK
    assert res.cited_ids == res.retrieved_ids  # ranked ids are the citations
    assert "KEV-CVE-2021-44228" in res.cited_ids


def test_run_item_cve_cited_ids_are_body_citations(service):  # Review Focus 4
    # Distinguish body-citation derivation from "ranked ids": a cve OK answer's cited_ids come
    # from parsing the report body, and equal the single scoped id.
    item = EvalItem(
        id="t",
        kind="cve",
        query="CVE-2099-0002",
        role="senior_analyst",
        expected_outcome=Outcome.OK,
        gold_document_ids=frozenset({"CVE-2099-0002"}),
    )
    res = run_item(service, item)
    assert res.cited_ids == ("CVE-2099-0002",)
    assert "# Research report:" in res.answer  # proves it parsed a report, not a search line


def test_run_benchmark_is_deterministic(service):
    items = [
        EvalItem(
            id=str(i),
            kind="search",
            query="powershell",
            role="research_analyst",
            expected_outcome=Outcome.OK,
            gold_document_ids=frozenset(),
        )
        for i in range(3)
    ]
    assert run_benchmark(service, items) == run_benchmark(service, items)
