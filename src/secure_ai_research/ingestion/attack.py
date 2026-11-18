"""MITRE ATT&CK ingestion — **stub** (ROADMAP Phase 2).

Parse the ATT&CK STIX bundle into :class:`ResearchDocument` records — one per
technique — so analyses can correlate vulnerabilities with adversary behavior.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secure_ai_research.ingestion.schema import ResearchDocument


def load(raw: bytes) -> list[ResearchDocument]:
    """Parse raw ATT&CK bundle bytes into research documents (not yet implemented)."""
    raise NotImplementedError(
        "ATT&CK ingestion — ROADMAP Phase 2 (weeks 5-8): parse the ATT&CK bundle into "
        "hash-pinned PUBLIC ResearchDocuments"
    )
