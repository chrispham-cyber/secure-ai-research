"""Evaluation metrics (ROADMAP Phase 4, Week 13).

Deterministic metrics over the REAL pipeline's output (carried in an ``EvalResult``): they
measure the **pipeline** — how well its cited answers are grounded, how accurate its
citations are, and whether it refused when it should — not a model. In posture there is no
generation step; model-behavior metrics (does a generator follow injected instructions, does
it hallucinate) live behind the Phase-4 ``Generator`` seam and are deferred.

"uncited answers score zero": a claim line with no citation is counted and scores zero, never
silently skipped.
"""

from __future__ import annotations

from secure_ai_research.evaluation.records import EvalResult
from secure_ai_research.reporting.report import citation_ids
from secure_ai_research.research_service import Outcome


def grounded_line_counts(answer: str, retrieved: set[str]) -> tuple[int, int]:
    """``(claim_lines, grounded_lines)`` over an answer body.

    The shared line-classification that both :func:`grounding` and the raw-model hallucination
    metric use, so neither can drift from ``build_report``'s drop rule. The report's title, the
    ``Sources:`` line, blank lines, and ``No cited findings.`` are structural, not claims. A
    claim line is *grounded* iff it carries at least one citation and every cited id is in
    ``retrieved``.
    """
    claims = 0
    grounded = 0
    for raw in answer.splitlines():
        line = raw.strip()
        if (
            not line
            or line.startswith("# Research report:")
            or line.startswith("Sources:")
            or line == "No cited findings."
        ):
            continue
        claims += 1
        ids = citation_ids(line)
        if ids and all(cid in retrieved for cid in ids):
            grounded += 1
    return claims, grounded


def grounding(result: EvalResult) -> float:
    """Fraction of answer claim-lines grounded in a retrieved citation.

    A body line is *grounded* iff it carries at least one citation and every cited id is in
    ``result.retrieved_ids``. The report's title / ``Sources:`` / blank / ``No cited
    findings.`` lines are not claims. With no claim lines, grounding is ``1.0`` (nothing
    false was claimed).
    """
    claims, grounded = grounded_line_counts(result.answer, set(result.retrieved_ids))
    return 1.0 if claims == 0 else grounded / claims


def citation_accuracy(result: EvalResult) -> float:
    """Fraction of the answer's cited ids that are gold (relevant) ids.

    With no citations, accuracy is ``1.0`` only when nothing was expected (``gold`` empty),
    else ``0.0`` — an answer that should have cited but did not is not perfectly accurate.
    """
    cited = set(result.cited_ids)
    gold = result.item.gold_document_ids
    if not cited:
        return 1.0 if not gold else 0.0
    return len(cited & gold) / len(cited)


def refusal_correct(result: EvalResult) -> bool:
    """True iff the pipeline's outcome matched the item's expected outcome.

    In posture there is no model to "refuse"; the deny / not-found / error decision is the
    pipeline's, so a correct refusal is simply the expected ``Outcome`` being produced.
    """
    return result.outcome == result.item.expected_outcome


def aggregate(results: list[EvalResult]) -> dict[str, float]:
    """Mean of each metric over its applicable items, plus counts (every value a float).

    ``grounding`` averages over **answered** cve/attack items, ``citation_accuracy`` over
    answered cve/attack/search items, ``refusal_accuracy`` over **all** items. An empty
    subset scores ``1.0`` (vacuous — no item failed). Iterates ``results`` in list order, so
    the result is deterministic.
    """
    answered = [r for r in results if r.outcome == Outcome.OK]

    def _mean(values: list[float]) -> float:
        return sum(values) / len(values) if values else 1.0

    return {
        "grounding": _mean([grounding(r) for r in answered if r.item.kind in {"cve", "attack"}]),
        "citation_accuracy": _mean(
            [citation_accuracy(r) for r in answered if r.item.kind in {"cve", "attack", "search"}]
        ),
        "refusal_accuracy": _mean([float(refusal_correct(r)) for r in results]),
        "n_total": float(len(results)),
        "n_answered": float(len(answered)),
    }
