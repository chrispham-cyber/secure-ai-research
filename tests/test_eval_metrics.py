"""Evaluation metrics (ROADMAP Phase 4, Week 13)."""

from secure_ai_research.evaluation.metrics import grounding
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
