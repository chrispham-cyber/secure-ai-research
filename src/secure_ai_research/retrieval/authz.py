"""Authorization gate for retrieval (ROADMAP Phase 2).

Core rule: **authorization is applied before retrieval, never after generation.**
A document the caller's role may not access never enters the retrieval set, so
there is nothing to leak in the answer. Filtering after generation would be a
control that has already failed.

Deny-by-default: only the two roles ``roles.md`` grants corpus retrieval
(``research_analyst``, ``senior_analyst``) are allowed, and only for a document
whose attributes also permit access (RBAC + ABAC). In this PUBLIC-only repo every
document is PUBLIC; the same gate works unchanged when more lanes exist.
"""

from __future__ import annotations

from secure_ai_research.ingestion.schema import Classification, ResearchDocument

_ALLOWED_ROLES = frozenset({"research_analyst", "senior_analyst"})


def authorize(role: str, doc: ResearchDocument) -> bool:
    """Return whether ``role`` may retrieve ``doc``.

    True only if the (whitespace-stripped) role is on the retrieval allowlist
    **and** the document's attributes permit access. Any other or empty role is
    denied.
    """
    return role.strip() in _ALLOWED_ROLES and doc.classification == Classification.PUBLIC
