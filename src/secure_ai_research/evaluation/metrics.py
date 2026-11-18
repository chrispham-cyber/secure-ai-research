"""Evaluation metrics — **stub** (ROADMAP Phase 4).

Phase 4 measures grounding and citation accuracy, not just surface overlap: an
answer with no supporting citation scores zero regardless of how correct it
reads.
"""

from __future__ import annotations


def score(predictions: list[str], gold: list[str]) -> dict[str, float]:
    """Score predictions against a gold set (not yet implemented)."""
    raise NotImplementedError(
        "Evaluation — ROADMAP Phase 4 (weeks 13-16): score grounding and citation "
        "accuracy; uncited answers score zero"
    )
