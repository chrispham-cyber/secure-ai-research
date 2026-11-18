"""CISA KEV ingestion — **stub** (ROADMAP Phase 2).

Parse the CISA Known Exploited Vulnerabilities catalog into
:class:`ResearchDocument` records, flagging which CVEs are known-exploited so
retrieval can prioritize them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secure_ai_research.ingestion.schema import ResearchDocument


def load(raw: bytes) -> list[ResearchDocument]:
    """Parse raw KEV catalog bytes into research documents (not yet implemented)."""
    raise NotImplementedError(
        "KEV ingestion — ROADMAP Phase 2 (weeks 5-8): parse the CISA KEV catalog into "
        "hash-pinned PUBLIC ResearchDocuments"
    )
