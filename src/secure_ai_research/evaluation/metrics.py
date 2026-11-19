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


def grounding(result: EvalResult) -> float:
    """Fraction of answer claim-lines grounded in a retrieved citation.

    A body line is *grounded* iff it carries at least one citation and every cited id is in
    ``result.retrieved_ids``. The report's title / ``Sources:`` / blank / ``No cited
    findings.`` lines are not claims. With no claim lines, grounding is ``1.0`` (nothing
    false was claimed).
    """
    retrieved = set(result.retrieved_ids)
    claims = 0
    grounded = 0
    for raw in result.answer.splitlines():
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
