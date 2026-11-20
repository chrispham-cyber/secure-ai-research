"""Hermetic CI gate over raw model-behaviour (SAIR follow-up #3).

Scores a generator's RAW, pre-filter output — captured through the real ``ask()`` pipeline — on
the three model-behaviour metrics, comparing values (never report bytes) against
``MODEL_BEHAVIOR_THRESHOLDS``. No LLM, no network: scripted stand-in generators drive it.

HONESTY: a green run proves the harness DISCRIMINATES (the unsafe generators each fail their
metric) and that a SCRIPTED baseline is clean. It does NOT prove a real model is safe — the
live-model numbers run behind ``-m integration``. Guarded against a vacuous pass: an answerable
floor, a non-zero raw-claim-line count, injection coverage, and a load-bearing check that each
unsafe generator trips its own threshold.
"""

from secure_ai_research.evaluation.benchmark import build_benchmark_service
from secure_ai_research.evaluation.model_eval import (
    GroundedGenerator,
    HallucinatingGenerator,
    InjectionFollowingGenerator,
    RefusingGenerator,
    collect_model_behavior_run,
)
from secure_ai_research.evaluation.thresholds import (
    MODEL_BEHAVIOR_THRESHOLDS,
    evaluate_thresholds,
)

_ANSWERABLE_FLOOR = 3  # the 4 _QA_ITEMS all retrieve; a collapse below this is a regression


def _values(gen, tmp_path, name):
    return collect_model_behavior_run(gen, tmp_path / name)


def test_safe_baseline_meets_all_model_behavior_thresholds(tmp_path):
    run = _values(GroundedGenerator(), tmp_path, "base.jsonl")
    failed = [
        c.name for c in evaluate_thresholds(run.values, MODEL_BEHAVIOR_THRESHOLDS) if not c.passed
    ]
    assert failed == []


def test_model_behavior_gate_is_not_vacuous(tmp_path):  # Review Focus 2
    run = _values(GroundedGenerator(), tmp_path, "v.jsonl")
    assert run.n_answerable >= _ANSWERABLE_FLOOR
    assert run.n_raw_claim_lines > 0
    assert run.injection_total > 0


def test_model_behavior_gate_fails_for_unsafe_generators(tmp_path):  # Review Focus 2 (load-bearing)
    for gen, metric, fname in [
        (HallucinatingGenerator(), "raw_hallucination_rate", "h.jsonl"),
        (RefusingGenerator(), "false_refusal_rate", "r.jsonl"),
        (InjectionFollowingGenerator(), "injection_following_rate", "i.jsonl"),
    ]:
        run = _values(gen, tmp_path, fname)
        failed = {
            c.name
            for c in evaluate_thresholds(run.values, MODEL_BEHAVIOR_THRESHOLDS)
            if not c.passed
        }
        assert metric in failed


def test_model_behavior_gate_is_deterministic(tmp_path):
    a = _values(GroundedGenerator(), tmp_path, "a.jsonl")
    b = _values(GroundedGenerator(), tmp_path, "b.jsonl")
    assert a.values == b.values


def test_raw_hallucination_lines_are_dropped_by_the_pipeline(tmp_path):  # Review Focus 4
    # The gate scores RAW output, but the pipeline's own filter still drops the forged line: the
    # model-behaviour metric and the deterministic citation filter are complementary, not rivals.
    svc = build_benchmark_service(tmp_path / "p.jsonl", generator=HallucinatingGenerator())
    res = svc.ask("Apache Log4j remote code execution", role="research_analyst")
    assert "CVE-0000-0000" not in res.answer and "fully compromised" not in res.answer
