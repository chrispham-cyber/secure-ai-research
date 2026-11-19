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

# Opt-in live fetch-on-miss does network egress and WRITES (it indexes the fetched document),
# and — absent a role gate — whether a fetch fires reveals to the caller whether a RESTRICTED
# document is present (absent id → fetch; present-but-RESTRICTED → no fetch), a timing/egress
# existence oracle. So live-fetch is a privileged capability: only a role for which authorize()
# never withholds a PUBLIC document (no present-but-hidden class) may trigger it — for such a
# role a miss can only mean genuinely-absent, so the fire-or-not signal carries no withheld
# existence. That set is _RESTRICTED_ROLES today; widen it ONLY in lockstep with any new
# sensitivity tier, or the oracle reopens.
# Kept EXPLICIT (not an alias of _RESTRICTED_ROLES): extending the RESTRICTED-eligible roles
# must not silently widen who may fetch. The binding invariant — every role here is authorize()d
# for a PUBLIC document at EVERY Sensitivity tier (no present-but-hidden class) — is pinned by
# test_fetch_roles_can_retrieve_every_sensitivity_tier, so adding a tier a fetch-eligible role
# cannot see fails that test loudly instead of reopening the oracle.
_FETCH_ROLES = frozenset({"senior_analyst"})


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


def may_live_fetch(role: str) -> bool:
    """Whether ``role`` may trigger opt-in live fetch-on-miss (see ``_FETCH_ROLES``)."""
    return role.strip() in _FETCH_ROLES
