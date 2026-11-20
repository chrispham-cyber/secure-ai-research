"""The IdentityProvider seam: its Protocol and error types (Phase 5, Slice 4).

Resolves an authenticated role from request credentials, replacing the self-asserted ``X-Role``
header (threat T1). An :class:`IdentityProvider` verifies ``Authorization: Bearer <jwt>`` (or, in
the off-by-default insecure dev mode, passes an ``X-Role`` through) and returns the role string
the downstream authorization gate consumes. Two failure types keep the API boundary honest:

- :class:`AuthError` — the client credential is missing, malformed, or rejected → 401 (and the
  request writes zero audit records; it never reached the service).
- :class:`IdentityUnavailable` — the identity backend or its configuration is broken → 503, so
  the system fails closed rather than falling back to an unauthenticated role.
"""

from __future__ import annotations

from typing import Protocol


class IdentityProvider(Protocol):
    """Resolves an authenticated role string from request credentials."""

    def identify(self, *, authorization: str, x_role: str) -> str: ...


class AuthError(Exception):
    """The client credential is missing, malformed, or rejected (→ 401)."""


class IdentityUnavailable(Exception):
    """The identity backend or its configuration is unavailable (→ 503, fail closed)."""
