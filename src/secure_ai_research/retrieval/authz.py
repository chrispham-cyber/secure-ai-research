"""Authorization gate for retrieval — **stub** (ROADMAP Phase 2).

Core rule: **authorization is applied before retrieval, never after generation.**
The model never sees a document the caller's role may not access, so there is
nothing to leak in the generated answer. Filtering after generation would be a
control that has already failed — the protected text would already have reached
the model.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secure_ai_research.ingestion.schema import ResearchDocument


def authorize(role: str, doc: ResearchDocument) -> bool:
    """Return whether ``role`` may access ``doc`` (not yet implemented).

    Called before a document enters the retrieval set: authorization is applied
    before retrieval, never after generation.
    """
    raise NotImplementedError(
        "Authorization gate — ROADMAP Phase 2 (weeks 5-8): authorization is applied "
        "before retrieval, never after generation"
    )
