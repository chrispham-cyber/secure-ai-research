"""Acceptance-threshold table + fail-loud comparator (Phase 4, Week 15)."""

import pytest

from secure_ai_research.evaluation.thresholds import (
    MODEL_BEHAVIOR_THRESHOLDS,
    THRESHOLDS,
    ThresholdCheck,
    evaluate_thresholds,
)

_BASELINE = {  # Week-14 measured aggregate + red-team ideals
    "grounding": 1.0,
    "citation_accuracy": 0.7742424242424243,
    "refusal_accuracy": 1.0,
    "injection_robustness": 1.0,
    "info_disclosures": 0.0,
}


def test_threshold_table_covers_the_five_metrics():
    assert {t.name for t in THRESHOLDS} == {
        "grounding",
        "citation_accuracy",
        "refusal_accuracy",
        "injection_robustness",
        "info_disclosures",
    }


def test_citation_accuracy_bound_is_measured_baseline_not_one():
    # Ruling: a 1.0 bound would fail the gate on benign deterministic search noise.
    ca = next(t for t in THRESHOLDS if t.name == "citation_accuracy")
    assert ca.mode == "min" and ca.bound < 1.0 and ca.bound <= 0.7742424242424243


def test_evaluate_thresholds_all_pass_at_baseline():
    checks = evaluate_thresholds(_BASELINE)
    assert all(c.passed for c in checks)
    assert len(checks) == 5
    assert all(isinstance(c, ThresholdCheck) for c in checks)


def test_evaluate_thresholds_flags_below_bound():  # Review Focus 4
    bad = {**_BASELINE, "grounding": 0.5}
    failed = [c for c in evaluate_thresholds(bad) if not c.passed]
    assert [c.name for c in failed] == ["grounding"]


def test_evaluate_thresholds_info_disclosures_is_a_max_bound():
    bad = {**_BASELINE, "info_disclosures": 1.0}
    assert not next(c for c in evaluate_thresholds(bad) if c.name == "info_disclosures").passed


def test_evaluate_thresholds_raises_on_missing_metric():  # Review Focus 4 (no vacuous pass)
    with pytest.raises(KeyError):
        evaluate_thresholds({"grounding": 1.0})


# --- Task 4: parallel model-behavior table + table-parameterized comparator -----------------


def test_model_behavior_table_passes_a_clean_baseline():
    clean = {
        "raw_hallucination_rate": 0.0,
        "false_refusal_rate": 0.0,
        "injection_following_rate": 0.0,
    }
    checks = evaluate_thresholds(clean, MODEL_BEHAVIOR_THRESHOLDS)
    assert [c.name for c in checks] == [t.name for t in MODEL_BEHAVIOR_THRESHOLDS]
    assert all(c.passed for c in checks)


def test_model_behavior_table_fails_a_nonzero_value():
    bad = {
        "raw_hallucination_rate": 0.2,
        "false_refusal_rate": 0.0,
        "injection_following_rate": 0.0,
    }
    failed = [c.name for c in evaluate_thresholds(bad, MODEL_BEHAVIOR_THRESHOLDS) if not c.passed]
    assert failed == ["raw_hallucination_rate"]


def test_default_table_is_unchanged():  # Review Focus 3
    # the default (no table arg) still iterates the Phase-4 THRESHOLDS, in order
    vals = {
        "grounding": 1.0,
        "citation_accuracy": 0.8,
        "refusal_accuracy": 1.0,
        "injection_robustness": 1.0,
        "info_disclosures": 0.0,
    }
    assert [c.name for c in evaluate_thresholds(vals)] == [t.name for t in THRESHOLDS]
