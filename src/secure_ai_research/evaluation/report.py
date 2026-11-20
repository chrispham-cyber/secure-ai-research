"""Static evaluation report (ROADMAP Phase 4 Week 16).

Pure rendering: turns the measured threshold checks + per-kind counts into a self-contained
HTML string and a Markdown sibling. No templating dependency, no I/O, and no clock read inside —
the caller passes ``generated_at`` — so the same inputs render the same bytes. That is what lets
the regression gate consume metric *values* and never diff this file's bytes: a benign template
change here cannot break CI.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from secure_ai_research.evaluation.thresholds import ThresholdCheck

_TITLE = "Secure AI Research — Phase 4 Evaluation Report"
_BANNER = (
    "In-posture evaluation: deterministic, offline, no LLM. Model-behavior evals "
    "(refusal / hallucination / injection-following) are not included in this report; they run "
    "as a scripted-baseline CI gate and, against a live model, behind the -m integration marker."
)
# Shown instead of _BANNER when a model-behavior section is present (model_checks non-empty).
_MODEL_BANNER = (
    "In-posture evaluation: deterministic, offline, no LLM. The model-behavior metrics below are "
    "measured on a SCRIPTED baseline generator — raw, pre-filter output driven through the real "
    "ask() pipeline. They prove the gate DISCRIMINATES (it catches an unsafe generator), not that "
    "a real model is safe. Live-model numbers run behind the -m integration marker."
)
_MODEL_SECTION_NOTE = (
    "Scripted baseline (strict zero bound). A real model is not expected to score 0.0; its numbers "
    "are reported as an observed ceiling under -m integration, never a hard CI bound."
)


def _status(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


def _op(mode: str) -> str:
    return ">=" if mode == "min" else "<="


def _metric_row_md(c: ThresholdCheck) -> str:
    return f"| {c.name} | {c.value:.4f} | {_op(c.mode)} {c.bound:.4f} | {_status(c.passed)} |"


def render_markdown(
    checks: Sequence[ThresholdCheck],
    by_kind: Mapping[str, int],
    n_total: int,
    n_answered: int,
    generated_at: str,
    model_checks: Sequence[ThresholdCheck] = (),
) -> str:
    overall = _status(all(c.passed for c in (*checks, *model_checks)))
    banner = _MODEL_BANNER if model_checks else _BANNER
    lines = [
        f"# {_TITLE}",
        "",
        f"_Generated: {generated_at}_",
        "",
        f"> {banner}",
        "",
        f"**Overall: {overall}** — {n_answered}/{n_total} items answered.",
        "",
        "## Metrics vs. thresholds",
        "",
        "| Metric | Value | Bound | Result |",
        "| --- | --- | --- | --- |",
    ]
    lines += [_metric_row_md(c) for c in checks]
    if model_checks:
        lines += [
            "",
            "## Model-behavior (scripted baseline)",
            "",
            f"> {_MODEL_SECTION_NOTE}",
            "",
            "| Metric | Value | Bound | Result |",
            "| --- | --- | --- | --- |",
        ]
        lines += [_metric_row_md(c) for c in model_checks]
    lines += ["", "## Benchmark items by kind", "", "| Kind | Count |", "| --- | --- |"]
    for kind, count in by_kind.items():
        lines.append(f"| {kind} | {count} |")
    lines.append("")
    return "\n".join(lines)


def _metric_row_html(c: ThresholdCheck) -> str:
    return (
        f"      <tr><td>{c.name}</td><td>{c.value:.4f}</td>"
        f"<td>{_op(c.mode)} {c.bound:.4f}</td>"
        f'<td class="{c.passed and "pass" or "fail"}">{_status(c.passed)}</td></tr>'
    )


def render_html(
    checks: Sequence[ThresholdCheck],
    by_kind: Mapping[str, int],
    n_total: int,
    n_answered: int,
    generated_at: str,
    model_checks: Sequence[ThresholdCheck] = (),
) -> str:
    overall = _status(all(c.passed for c in (*checks, *model_checks)))
    banner = _MODEL_BANNER if model_checks else _BANNER
    metric_rows = "\n".join(_metric_row_html(c) for c in checks)
    kind_rows = "\n".join(
        f"      <tr><td>{kind}</td><td>{count}</td></tr>" for kind, count in by_kind.items()
    )
    model_section = ""
    if model_checks:
        model_rows = "\n".join(_metric_row_html(c) for c in model_checks)
        model_section = f"""  <h2>Model-behavior (scripted baseline)</h2>
  <p class="banner">{_MODEL_SECTION_NOTE}</p>
  <table>
    <thead><tr><th>Metric</th><th>Value</th><th>Bound</th><th>Result</th></tr></thead>
    <tbody>
{model_rows}
    </tbody>
  </table>
"""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{_TITLE}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 48rem; }}
    .banner {{ background: #f3f0ff; border-left: 4px solid #6b46c1; padding: .75rem 1rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #ccc; padding: .4rem .6rem; text-align: left; }}
    .pass {{ color: #137333; font-weight: 600; }}
    .fail {{ color: #a50e0e; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>{_TITLE}</h1>
  <p><em>Generated: {generated_at}</em></p>
  <p class="banner">{banner}</p>
  <h2>Overall: <span class="{overall == "PASS" and "pass" or "fail"}">{overall}</span></h2>
  <p>{n_answered}/{n_total} items answered.</p>
  <h2>Metrics vs. thresholds</h2>
  <table>
    <thead><tr><th>Metric</th><th>Value</th><th>Bound</th><th>Result</th></tr></thead>
    <tbody>
{metric_rows}
    </tbody>
  </table>
{model_section}  <h2>Benchmark items by kind</h2>
  <table>
    <thead><tr><th>Kind</th><th>Count</th></tr></thead>
    <tbody>
{kind_rows}
    </tbody>
  </table>
</body>
</html>
"""


def render_report(
    checks: Sequence[ThresholdCheck],
    by_kind: Mapping[str, int],
    n_total: int,
    n_answered: int,
    generated_at: str,
    *,
    model_checks: Sequence[ThresholdCheck] = (),
) -> tuple[str, str]:
    """Render the evaluation report as ``(html, markdown)`` — pure, deterministic in its args.

    ``model_checks`` is keyword-only and defaults to empty, so every existing positional call is
    unaffected (the banner states the model-behavior evals are not in this report; no model
    section). When non-empty, both formats gain a
    "Model-behavior (scripted baseline)" section and the banner discloses the ``-m integration``
    scope — the shipped report is then honest that a real model is not what was scored.
    """
    html = render_html(checks, by_kind, n_total, n_answered, generated_at, model_checks)
    markdown = render_markdown(checks, by_kind, n_total, n_answered, generated_at, model_checks)
    return html, markdown
