"""Static evaluation report renderer: content + determinism (Phase 4, Week 16)."""

from secure_ai_research.evaluation.report import render_report
from secure_ai_research.evaluation.thresholds import evaluate_thresholds

_BASELINE = {
    "grounding": 1.0,
    "citation_accuracy": 0.7742424242424243,
    "refusal_accuracy": 1.0,
    "injection_robustness": 1.0,
    "info_disclosures": 0.0,
}
_BY_KIND = {"cve": 13, "attack": 12, "search": 15, "authz": 6, "injection": 5}
_METRICS = (
    "grounding",
    "citation_accuracy",
    "refusal_accuracy",
    "injection_robustness",
    "info_disclosures",
)


def test_report_names_every_metric_and_kind_in_both_formats():
    html, md = render_report(evaluate_thresholds(_BASELINE), _BY_KIND, 51, 30, "2026-11-19")
    for blob in (html, md):
        for name in _METRICS:
            assert name in blob
        for kind in _BY_KIND:
            assert kind in blob
        assert "2026-11-19" in blob


def test_report_shows_pass_and_the_deferred_banner():
    html, md = render_report(evaluate_thresholds(_BASELINE), _BY_KIND, 51, 30, "2026-11-19")
    assert "<html" in html.lower() and "PASS" in html and "PASS" in md
    assert "deferred" in html.lower() and "deferred" in md.lower()


def test_report_marks_fail_when_a_check_fails():
    bad = evaluate_thresholds({**_BASELINE, "grounding": 0.0})
    html, md = render_report(bad, _BY_KIND, 51, 30, "2026-11-19")
    assert "FAIL" in html and "FAIL" in md


def test_report_is_deterministic_given_a_fixed_timestamp():  # Review Focus 3
    args = (evaluate_thresholds(_BASELINE), _BY_KIND, 51, 30, "2026-11-19")
    assert render_report(*args) == render_report(*args)
