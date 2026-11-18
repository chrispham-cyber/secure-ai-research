"""Sigma detection-rule ingestion — **stub** (ROADMAP Phase 2).

Parse public Sigma detection rules into :class:`ResearchDocument` records so
retrieval can tie a vulnerability or technique to the detections that cover it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secure_ai_research.ingestion.schema import ResearchDocument


def load(raw: bytes) -> list[ResearchDocument]:
    """Parse raw Sigma rule bytes into research documents (not yet implemented)."""
    raise NotImplementedError(
        "Sigma ingestion — ROADMAP Phase 2 (weeks 5-8): parse Sigma rules into "
        "hash-pinned PUBLIC ResearchDocuments"
    )
