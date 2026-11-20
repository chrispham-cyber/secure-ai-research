"""Hermetic unit tests for the raw-model-behavior eval layer (SAIR follow-up #3).

These cover the pure metric functions (raw hallucination, false refusal) and the shared
groundedness primitive they borrow from the pipeline, plus the scripted generators and the
``collect_model_behavior_run`` assembly. No LLM, no network — the scripted generators stand in
for a model, and the real ``ask()`` pipeline runs underneath.
"""

from __future__ import annotations

from secure_ai_research.evaluation.metrics import grounded_line_counts
from secure_ai_research.evaluation.model_eval import (
    _is_refusal,
    false_refusal_rate,
    raw_hallucination_rate,
)


def test_grounded_line_counts_skips_structural_lines_and_scores_claims():
    answer = "# Research report: x\n\nFinding [CVE-2021-44228]\nSources: a, b\nNo cited findings."
    assert grounded_line_counts(answer, {"CVE-2021-44228"}) == (1, 1)


def test_grounded_line_counts_marks_a_forged_id_ungrounded():
    assert grounded_line_counts("Bad [CVE-0000-0000]", {"CVE-2021-44228"}) == (1, 0)


def test_is_refusal_detects_decline_and_blank():
    assert _is_refusal("I cannot help with that request.") is True
    assert _is_refusal("   ") is True
    assert _is_refusal("Here is a grounded finding [CVE-2021-44228].") is False


def test_raw_hallucination_rate_pools_ungrounded_over_claim_lines():
    samples = [("Good [CVE-2021-44228]\nBad [CVE-0000-0000]", frozenset({"CVE-2021-44228"}))]
    assert raw_hallucination_rate(samples) == 0.5


def test_raw_hallucination_rate_excludes_refusals_and_empty_is_zero():
    assert raw_hallucination_rate([("I cannot answer that.", frozenset())]) == 0.0
    assert raw_hallucination_rate([]) == 0.0


def test_false_refusal_rate_is_the_refused_fraction():
    assert false_refusal_rate(["I cannot help.", "Grounded answer [CVE-2021-44228]."]) == 0.5
    assert false_refusal_rate([]) == 0.0
