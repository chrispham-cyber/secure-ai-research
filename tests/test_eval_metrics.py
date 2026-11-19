"""Evaluation metrics (ROADMAP Phase 4, Week 13)."""

from secure_ai_research.evaluation.metrics import (
    aggregate,
    citation_accuracy,
    grounding,
    refusal_correct,
)
from secure_ai_research.evaluation.records import EvalItem, EvalResult, ItemKind
from secure_ai_research.research_service import Outcome


def _ok(answer: str, retrieved: list[str], kind: ItemKind = "cve") -> EvalResult:
    item = EvalItem(
        id="x",
        kind=kind,
        query="q",
        role="research_analyst",
        expected_outcome=Outcome.OK,
        gold_document_ids=frozenset(retrieved),
    )
    return EvalResult(
        item=item,
        outcome=Outcome.OK,
        cited_ids=tuple(retrieved),
        retrieved_ids=tuple(retrieved),
        answer=answer,
    )


def test_grounding_all_cited_is_one():
    ans = "# Research report: q\n\nrce [CVE-2021-44228]\n\nSources: CVE-2021-44228"
    assert grounding(_ok(ans, ["CVE-2021-44228"])) == 1.0


def test_grounding_uncited_line_scores_zero():  # Review Focus 1 (load-bearing)
    ans = (
        "# Research report: q\n\nrce [CVE-2021-44228]\nbackdoor with no citation\n\n"
        "Sources: CVE-2021-44228"
    )
    assert grounding(_ok(ans, ["CVE-2021-44228"])) == 0.5


def test_grounding_cited_to_unretrieved_scores_zero():
    ans = "# Research report: q\n\nclaim [CVE-2099-0001]\n\nSources: CVE-2021-44228"
    assert grounding(_ok(ans, ["CVE-2021-44228"])) == 0.0


def test_citation_accuracy_all_gold_is_one():
    r = _ok("…", ["CVE-2021-44228"])
    assert citation_accuracy(r) == 1.0


def test_citation_accuracy_non_gold_citation_lowers_it():  # Review Focus 2
    item = EvalItem(
        id="x",
        kind="search",
        query="q",
        role="research_analyst",
        expected_outcome=Outcome.OK,
        gold_document_ids=frozenset({"KEV-CVE-2021-44228"}),
    )
    r = EvalResult(
        item=item,
        outcome=Outcome.OK,
        cited_ids=("KEV-CVE-2021-44228", "SIGMA-wrong"),
        retrieved_ids=("KEV-CVE-2021-44228", "SIGMA-wrong"),
        answer="…",
    )
    assert citation_accuracy(r) == 0.5


def test_citation_accuracy_empty_cited_against_gold_is_zero():
    item = EvalItem(
        id="x",
        kind="cve",
        query="q",
        role="research_analyst",
        expected_outcome=Outcome.OK,
        gold_document_ids=frozenset({"CVE-2021-44228"}),
    )
    r = EvalResult(item=item, outcome=Outcome.OK, cited_ids=(), retrieved_ids=(), answer="…")
    assert citation_accuracy(r) == 0.0


def test_refusal_correct_matches_expected_outcome():
    item = EvalItem(
        id="x",
        kind="cve",
        query="q",
        role="intern",
        expected_outcome=Outcome.DENIED,
        gold_document_ids=frozenset(),
    )
    denied = EvalResult(
        item=item,
        outcome=Outcome.DENIED,
        cited_ids=(),
        retrieved_ids=(),
        answer="",
    )
    served = EvalResult(item=item, outcome=Outcome.OK, cited_ids=(), retrieved_ids=(), answer="…")
    assert refusal_correct(denied) is True and refusal_correct(served) is False


def test_aggregate_denied_item_does_not_inflate_grounding():  # Review Focus 3
    ok = _ok(
        "# Research report: q\n\nrce [CVE-2021-44228]\n\nSources: CVE-2021-44228",
        ["CVE-2021-44228"],
    )
    denied_item = EvalItem(
        id="d",
        kind="cve",
        query="q",
        role="intern",
        expected_outcome=Outcome.DENIED,
        gold_document_ids=frozenset(),
    )
    # Non-empty UNCITED answer: grounding() scores this 0.0, so if aggregate wrongly folded
    # a non-answered item into the grounding subset the mean would drop to 0.5 (this is what
    # pins Review Focus 3 — an empty answer would score 1.0 and make the assertion vacuous).
    denied = EvalResult(
        item=denied_item,
        outcome=Outcome.DENIED,
        cited_ids=(),
        retrieved_ids=(),
        answer="backdoor planted, no citation",
    )
    agg = aggregate([ok, denied])
    assert agg["grounding"] == 1.0 and agg["n_answered"] == 1.0 and agg["n_total"] == 2.0
    assert agg["refusal_accuracy"] == 1.0  # ok→OK expected OK, denied→DENIED expected DENIED


def test_aggregate_empty_is_defined_not_crash():  # Review Focus 4
    agg = aggregate([])
    assert agg == {
        "grounding": 1.0,
        "citation_accuracy": 1.0,
        "refusal_accuracy": 1.0,
        "n_total": 0.0,
        "n_answered": 0.0,
    }
