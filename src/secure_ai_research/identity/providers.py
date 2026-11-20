"""Identity providers for the default (local HS256) and insecure (X-Role) modes — Slice 4.

- :class:`LocalTokenIdentityProvider` verifies a Bearer HS256 token with a shared secret — the
  offline default, so the role is authenticated, not self-asserted. ``X-Role`` is ignored.
- :class:`InsecureIdentityProvider` trusts the ``X-Role`` header verbatim: the pre-Slice-4
  behaviour, kept only as an off-by-default dev escape hatch (the factory logs a warning when it
  is selected).

The OIDC/RS256 provider lives in ``oidc.py`` behind the opt-in ``[oidc]`` extra.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from secure_ai_research.identity.ports import AuthError
from secure_ai_research.identity.tokens import verify_hs256


class LocalTokenIdentityProvider:
    """Verifies ``Authorization: Bearer <HS256 jwt>`` with a shared secret (the offline default)."""

    def __init__(
        self,
        secret: str,
        *,
        role_claim: str = "role",
        now: Callable[[], float] = time.time,
    ) -> None:
        self._secret = secret
        self._role_claim = role_claim
        self._now = now

    def identify(self, *, authorization: str, x_role: str) -> str:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise AuthError("expected a Bearer token")
        claims = verify_hs256(token.strip(), self._secret, now=self._now())
        role = claims.get(self._role_claim)
        return role.strip() if isinstance(role, str) else ""


class InsecureIdentityProvider:
    """Trusts the ``X-Role`` header verbatim (off-by-default dev escape hatch — spoofable)."""

    def identify(self, *, authorization: str, x_role: str) -> str:
        return x_role.strip()
