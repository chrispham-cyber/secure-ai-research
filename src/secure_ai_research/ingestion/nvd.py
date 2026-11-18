"""NVD ingestion — **stub** (ROADMAP Phase 2).

Parse an NVD CVE feed into validated :class:`ResearchDocument` records: one per
CVE, classification pinned to PUBLIC, each carrying a ``sha256:`` integrity hash
of its source payload so downstream retrieval can prove provenance.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secure_ai_research.ingestion.schema import ResearchDocument


def load(raw: bytes) -> list[ResearchDocument]:
    """Parse raw NVD feed bytes into research documents (not yet implemented)."""
    raise NotImplementedError(
        "NVD ingestion — ROADMAP Phase 2 (weeks 5-8): parse the NVD feed into "
        "hash-pinned PUBLIC ResearchDocuments"
    )
