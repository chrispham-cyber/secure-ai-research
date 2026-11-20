"""Evaluation runner: shared assembly + report writing (Phase 4, Week 16)."""

import pytest

from secure_ai_research.evaluation.benchmark import build_benchmark_service
from secure_ai_research.evaluation.run import EvalRun, collect_eval_run, main
from secure_ai_research.evaluation.thresholds import THRESHOLDS


@pytest.fixture
def service(tmp_path):
    return build_benchmark_service(tmp_path / "audit.jsonl")


def test_collect_eval_run_keys_match_the_thresholds_table(service):
    run = collect_eval_run(service)
    assert isinstance(run, EvalRun)
    assert set(run.values) == {t.name for t in THRESHOLDS}


def test_collect_eval_run_maps_redteam_fields_to_threshold_keys(service):
    run = collect_eval_run(service)
    # robustness -> injection_robustness, disclosures -> info_disclosures
    assert run.values["injection_robustness"] == 1.0
    assert run.values["info_disclosures"] == 0.0
    assert run.injection_total > 0 and run.injection_retrieved == run.injection_total


def test_main_writes_both_report_files_and_returns_zero(tmp_path):
    rc = main(out_dir=tmp_path)
    assert rc == 0
    assert (tmp_path / "phase4-eval-report.html").is_file()
    assert (tmp_path / "phase4-eval-report.md").is_file()
    assert "grounding" in (tmp_path / "phase4-eval-report.md").read_text()
