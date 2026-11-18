"""Report rendering — **stub** (ROADMAP Phase 2).

Render a research record into a human-reviewable report. Every claim must point
back to a retrieved document id; a claim with no citation is omitted, never
shown as fact.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secure_ai_research.audit.record import ResearchRecord


def build_report(record: ResearchRecord) -> str:
    """Render a research record into a cited, reviewable report (not yet implemented)."""
    raise NotImplementedError(
        "Reporting — ROADMAP Phase 2 (weeks 5-8): render a cited report where every "
        "claim links to a retrieved document id"
    )
