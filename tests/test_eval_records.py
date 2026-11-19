"""Typed evaluation records (ROADMAP Phase 4, Week 13)."""

import pytest
from pydantic import ValidationError

from secure_ai_research.evaluation.records import EvalItem, EvalResult
from secure_ai_research.research_service import Outcome


def test_eval_item_defaults_and_frozen():
    item = EvalItem(
        id="i1",
        kind="cve",
        query="CVE-2021-44228",
        role="research_analyst",
        expected_outcome=Outcome.OK,
        gold_document_ids=frozenset({"CVE-2021-44228"}),
    )
    assert item.must_not_appear == frozenset() and item.note == ""
    assert item.expected_outcome is Outcome.OK
    with pytest.raises(ValidationError):
        item.role = "senior_analyst"  # frozen


def test_eval_result_holds_pipeline_shape():
    item = EvalItem(
        id="i1",
        kind="search",
        query="log4j",
        role="research_analyst",
        expected_outcome=Outcome.OK,
        gold_document_ids=frozenset(),
    )
    res = EvalResult(
        item=item,
        outcome=Outcome.OK,
        cited_ids=("KEV-CVE-2021-44228",),
        retrieved_ids=("KEV-CVE-2021-44228",),
        answer="…",
    )
    assert res.item.kind == "search" and res.outcome is Outcome.OK
