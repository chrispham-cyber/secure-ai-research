"""Injection-robustness red-team eval over the real pipeline (Phase 4, Week 15)."""

import pytest

from secure_ai_research.evaluation.benchmark import build_benchmark_service
from secure_ai_research.evaluation.injection_corpus import malicious_corpus
from secure_ai_research.evaluation.redteam import run_injection_eval


@pytest.fixture
def service(tmp_path):
    return build_benchmark_service(tmp_path / "a.jsonl")


def test_injection_robustness_is_total_neutralization(service):
    r = run_injection_eval(service)
    assert r.total == len(malicious_corpus())
    assert r.failures == ()
    assert r.neutralized == r.total
    assert r.robustness == 1.0


def test_injection_eval_actually_retrieves_every_lure(service):  # Review Focus 2 (non-vacuous)
    r = run_injection_eval(service)
    assert set(r.retrieved) == {d.document.document_id for d in malicious_corpus()}


def test_injection_forged_ids_never_surface(service):
    # The forged/impersonated bracket ids embedded in the payloads must not appear as
    # structured citations or rendered text for research_analyst.
    r = run_injection_eval(service)
    assert r.robustness == 1.0 and r.failures == ()
