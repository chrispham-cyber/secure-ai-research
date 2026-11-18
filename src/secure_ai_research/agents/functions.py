"""Agent-callable functions — **stub** (ROADMAP Phase 3).

Core rule: **the model may *request* a function; the application independently
decides if it is permitted (checks live outside the LLM).** The model's output is
treated as an untrusted request, not an authorized command: argument validation,
rate limits, and role checks run in this module, never inside the prompt.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secure_ai_research.ingestion.schema import ResearchDocument

_RULE = (
    "the model may request a function; the application independently decides if it is "
    "permitted (checks live outside the LLM)"
)


def search_cve(cve_id: str) -> list[ResearchDocument]:
    """Look up a CVE by id, if the caller is permitted (not yet implemented)."""
    raise NotImplementedError(f"Agent tool search_cve — ROADMAP Phase 3 (weeks 9-12): {_RULE}")


def search_attack(technique_id: str) -> list[ResearchDocument]:
    """Look up an ATT&CK technique, if the caller is permitted (not yet implemented)."""
    raise NotImplementedError(f"Agent tool search_attack — ROADMAP Phase 3 (weeks 9-12): {_RULE}")


def search_research(query: str) -> list[ResearchDocument]:
    """Evidence-grounded semantic search, if the caller is permitted (not yet implemented)."""
    raise NotImplementedError(f"Agent tool search_research — ROADMAP Phase 3 (weeks 9-12): {_RULE}")
