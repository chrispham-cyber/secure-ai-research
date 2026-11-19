"""Authorization gate for retrieval (ROADMAP Phase 2).

Core rule: **authorization is applied before retrieval, never after generation.**
A document the caller's role may not access never enters the retrieval set, so
there is nothing to leak in the answer. Filtering after generation would be a
control that has already failed.

Deny-by-default: only the two roles ``roles.md`` grants corpus retrieval
(``research_analyst``, ``senior_analyst``) are allowed, and only for a document
whose attributes also permit access (RBAC + ABAC). Every document is PUBLIC; within
that lane a ``RESTRICTED`` sensitivity tier narrows the wider-scope documents to
``senior_analyst``, so the two retrieval roles no longer see an identical corpus.
"""

from __future__ import annotations

from secure_ai_research.ingestion.schema import Classification, ResearchDocument, Sensitivity

_ALLOWED_ROLES = frozenset({"research_analyst", "senior_analyst"})
# Wider-scope roles that may retrieve RESTRICTED documents (roles.md: senior_analyst).
_RESTRICTED_ROLES = frozenset({"senior_analyst"})


def authorize(role: str, doc: ResearchDocument) -> bool:
    """Return whether ``role`` may retrieve ``doc``.

    Deny-by-default, checked in order: the (whitespace-stripped) role must be on the
    retrieval allowlist (RBAC); the document must be PUBLIC; and a RESTRICTED document
    (the ABAC sensitivity tier) requires one of the wider-scope ``_RESTRICTED_ROLES``.
    Any other or empty role — and a RESTRICTED document for a non-senior role — is denied.
    """
    role = role.strip()
    if role not in _ALLOWED_ROLES:
        return False
    if doc.classification != Classification.PUBLIC:
        return False
    if doc.sensitivity == Sensitivity.RESTRICTED and role not in _RESTRICTED_ROLES:
        return False
    return True
