"""Hermetic unit tests for the raw-model-behavior eval layer (SAIR follow-up #3).

These cover the pure metric functions (raw hallucination, false refusal) and the shared
groundedness primitive they borrow from the pipeline, plus the scripted generators and the
``collect_model_behavior_run`` assembly. No LLM, no network — the scripted generators stand in
for a model, and the real ``ask()`` pipeline runs underneath.
"""

from __future__ import annotations

from secure_ai_research.evaluation.metrics import grounded_line_counts
from secure_ai_research.evaluation.model_eval import (
    GroundedGenerator,
    HallucinatingGenerator,
    InjectionFollowingGenerator,
    RecordingGenerator,
    RefusingGenerator,
    _is_refusal,
    false_refusal_rate,
    injection_following_rate,
    raw_hallucination_rate,
)
from secure_ai_research.generation.ports import Generator


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


# --- Task 2: recording wrapper + scripted generators ----------------------------------------


def test_scripted_generators_satisfy_the_protocol():
    for g in (
        GroundedGenerator(),
        HallucinatingGenerator(),
        RefusingGenerator(),
        InjectionFollowingGenerator(),
    ):
        assert isinstance(g, Generator)


def test_recording_generator_records_each_output_and_proxies_identity():
    rec = RecordingGenerator(GroundedGenerator())
    out = rec.generate("q", ["x [CVE-2021-44228]"])
    assert rec.outputs == [out]
    assert rec.model_id == "scripted-grounded"


def test_hallucinating_generator_emits_a_forged_uncited_id():
    out = HallucinatingGenerator().generate("q", ["x [CVE-2021-44228]"])
    assert "CVE-0000-0000" in out and "CVE-2021-44228" in out


def test_refusing_generator_is_detected_as_a_refusal():
    assert _is_refusal(RefusingGenerator().generate("q", ["x [CVE-2021-44228]"])) is True


def test_injection_following_generator_scores_high_refuser_low():
    assert injection_following_rate(InjectionFollowingGenerator()) == 1.0
    assert injection_following_rate(RefusingGenerator()) == 0.0
