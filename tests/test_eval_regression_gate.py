"""Hermetic CI regression gate over the benchmark + red-team metrics (Phase 4, Week 16).

Asserts every measured metric meets its acceptance threshold, over the *real* no-LLM pipeline,
comparing metric values (never report bytes) with stable ordering. Guarded against a vacuous
pass: non-zero item count per kind, an ``n_answered`` floor, full injection retrieval coverage,
and a load-bearing check that the gate fails when a threshold is unmet.
"""

import pytest

from secure_ai_research.evaluation.benchmark import build_benchmark_service
from secure_ai_research.evaluation.run import collect_eval_run
from secure_ai_research.evaluation.thresholds import THRESHOLDS, evaluate_thresholds

_N_ANSWERED_FLOOR = 25  # Week-14 measured 30; a collapse below this is a regression
_KINDS = ("cve", "attack", "search", "authz", "injection")


@pytest.fixture
def run(tmp_path):
    return collect_eval_run(build_benchmark_service(tmp_path / "audit.jsonl"))


def test_every_metric_meets_its_threshold(run):
    checks = evaluate_thresholds(run.values)
    failed = [(c.name, c.value, c.bound) for c in checks if not c.passed]
    assert failed == []
    assert len(checks) == len(THRESHOLDS)


def test_gate_is_not_vacuous(run):  # Review Focus 2
    assert run.n_answered >= _N_ANSWERED_FLOOR
    for kind in _KINDS:
        assert run.by_kind.get(kind, 0) > 0
    assert run.injection_total > 0 and run.injection_retrieved == run.injection_total
    assert run.info_probes >= 4


def test_gate_fails_when_a_threshold_is_unmet(run):  # Review Focus 1 (load-bearing)
    broken = {**run.values, "citation_accuracy": 0.4}
    failed = [c.name for c in evaluate_thresholds(broken) if not c.passed]
    assert failed == ["citation_accuracy"]


def test_gate_is_deterministic(tmp_path):  # Review Focus 3
    a = collect_eval_run(build_benchmark_service(tmp_path / "a.jsonl"))
    b = collect_eval_run(build_benchmark_service(tmp_path / "b.jsonl"))
    assert a.values == b.values and a.by_kind == b.by_kind
