"""Evaluation runner + report writer (ROADMAP Phase 4 Week 16).

``python -m secure_ai_research.evaluation.run`` runs the benchmark (Week 14) and red-team
(Week 15) evals on a throwaway audit log, assembles the metric values the thresholds table
(Week 15) names, writes the static report to ``reports/``, prints a deterministic summary, and
exits non-zero iff any threshold is unmet. It additionally runs the scripted model-behavior gate
(SAIR follow-up #3: raw hallucination / false refusal / injection-following over a baseline
generator, through the real ``ask()`` pipeline) and folds it into the same pass/fail and report —
a real model's numbers stay behind ``-m integration``, never a hard CI bound here.

``collect_eval_run`` is the single assembly both the CLI and the ``tests/test_eval_regression_gate``
gate consume — so the number the gate checks is the number the report shows. It maps the red-team
result fields onto the threshold keys (``robustness`` → ``injection_robustness``, ``disclosures``
→ ``info_disclosures``) so ``values`` keys equal ``THRESHOLDS`` names exactly.
"""

from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path
from tempfile import TemporaryDirectory

from pydantic import BaseModel, ConfigDict

from secure_ai_research.evaluation.benchmark import (
    benchmark_items,
    build_benchmark_service,
    run_benchmark,
)
from secure_ai_research.evaluation.metrics import aggregate
from secure_ai_research.evaluation.model_eval import (
    GroundedGenerator,
    collect_model_behavior_run,
)
from secure_ai_research.evaluation.redteam import run_info_disclosure_eval, run_injection_eval
from secure_ai_research.evaluation.report import render_report
from secure_ai_research.evaluation.thresholds import (
    MODEL_BEHAVIOR_THRESHOLDS,
    ThresholdCheck,
    evaluate_thresholds,
)
from secure_ai_research.research_service import ResearchService

_REPORT_STEM = "phase4-eval-report"


class EvalRun(BaseModel):
    """Everything the report and the gate need from one evaluation pass.

    ``values`` is keyed by the ``THRESHOLDS`` metric names; the rest are non-vacuity witnesses
    (so the gate can prove the run measured real items, not an empty set).
    """

    model_config = ConfigDict(frozen=True)

    values: dict[str, float]
    by_kind: dict[str, int]
    n_total: int
    n_answered: int
    injection_total: int
    injection_retrieved: int
    info_probes: int


def collect_eval_run(service: ResearchService) -> EvalRun:
    """Run benchmark + red-team evals against ``service`` and assemble the metric values."""
    items = benchmark_items()
    results = run_benchmark(service, items)
    agg = aggregate(results)
    injection = run_injection_eval(service)
    disclosure = run_info_disclosure_eval(service)

    values = {
        "grounding": agg["grounding"],
        "citation_accuracy": agg["citation_accuracy"],
        "refusal_accuracy": agg["refusal_accuracy"],
        "injection_robustness": injection.robustness,
        "info_disclosures": float(disclosure.disclosures),
    }
    return EvalRun(
        values=values,
        by_kind=dict(Counter(item.kind for item in items)),
        n_total=len(items),
        n_answered=int(agg["n_answered"]),
        injection_total=injection.total,
        injection_retrieved=len(injection.retrieved),
        info_probes=disclosure.probes,
    )


def _print_checks(checks: list[ThresholdCheck]) -> None:
    for check in checks:
        op = ">=" if check.mode == "min" else "<="
        status = "PASS" if check.passed else "FAIL"
        print(f"  {check.name}={check.value:.4f} ({op} {check.bound:.4f}) {status}")


def main(out_dir: Path = Path("reports")) -> int:
    """Run both gates, write the report to ``out_dir``, print a summary, return 0 iff all pass.

    The exit code folds in BOTH the Phase-4 pipeline gate and the scripted model-behavior gate: a
    non-zero return means at least one bound was unmet in either.
    """
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        run = collect_eval_run(build_benchmark_service(tmp_path / "audit.jsonl"))
        model_run = collect_model_behavior_run(GroundedGenerator(), tmp_path / "model-audit.jsonl")

    checks = evaluate_thresholds(run.values)
    model_checks = evaluate_thresholds(model_run.values, MODEL_BEHAVIOR_THRESHOLDS)
    html, markdown = render_report(
        checks,
        run.by_kind,
        run.n_total,
        run.n_answered,
        date.today().isoformat(),
        model_checks=model_checks,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{_REPORT_STEM}.html").write_text(html)
    (out_dir / f"{_REPORT_STEM}.md").write_text(markdown)

    print(f"evaluation: {run.n_answered}/{run.n_total} answered | by kind: {run.by_kind}")
    _print_checks(checks)
    print(
        "model-behavior (scripted baseline): "
        f"answerable={model_run.n_answerable}, raw_claim_lines={model_run.n_raw_claim_lines}"
    )
    _print_checks(model_checks)
    passed = all(c.passed for c in checks) and all(c.passed for c in model_checks)
    print(f"overall: {'PASS' if passed else 'FAIL'} | report: {out_dir / _REPORT_STEM}.{{html,md}}")
    return 0 if passed else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
