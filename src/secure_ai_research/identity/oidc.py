"""OIDC / RS256 identity provider (Phase 5, Slice 4) — opt-in, behind the ``[oidc]`` extra.

Verifies an OIDC access token (``Authorization: Bearer <RS256 jwt>``) against a Keycloak realm's
JWKS. ``pyjwt[crypto]`` is imported **lazily inside identify** (memoised on the instance), never at
module import or in ``__init__`` — so (a) the hermetic default suite never imports ``jwt``, and
(b) a missing extra or an unreachable JWKS endpoint surfaces as :class:`IdentityUnavailable` at
request time (→ 503, fail closed), not as a constructor error that a ``Depends`` would turn into an
unhandled 500.

Real RS256/JWKS decode is exercised only by the live Keycloak integration test (Task 7); the
hermetic venv has no ``pyjwt``.
"""

from __future__ import annotations

from typing import Any

from secure_ai_research.identity.ports import AuthError, IdentityUnavailable

_OIDC_EXTRA_HINT = "oidc extra not installed: pip install '.[oidc]'"


class OidcIdentityProvider:
    """Verifies a Bearer RS256 token against a realm's JWKS (opt-in production identity)."""

    def __init__(
        self,
        issuer: str,
        jwks_url: str,
        audience: str,
        *,
        role_claim: str = "role",
        timeout: float = 5.0,
    ) -> None:
        self._issuer = issuer
        self._jwks_url = jwks_url
        self._audience = audience
        self._role_claim = role_claim
        self._timeout = timeout
        self._jwt: Any = None
        self._client: Any = None

    def _ensure_client(self) -> Any:
        """Lazily import pyjwt and build the JWKS client once, failing closed on either problem."""
        if self._client is None:
            try:
                import jwt  # lazy: only when oidc mode is actually exercised
            except ImportError as exc:
                raise IdentityUnavailable(_OIDC_EXTRA_HINT) from exc
            try:
                self._client = jwt.PyJWKClient(
                    self._jwks_url, timeout=self._timeout, cache_keys=True
                )
            except Exception as exc:  # malformed URL / client construction → fail closed
                raise IdentityUnavailable(type(exc).__name__) from exc
            self._jwt = jwt
        return self._client

    def identify(self, *, authorization: str, x_role: str) -> str:
        scheme, _, raw = authorization.partition(" ")
        token = raw.strip()
        if scheme.lower() != "bearer" or not token:
            raise AuthError("expected a Bearer token")

        client = self._ensure_client()
        jwt = self._jwt
        try:
            signing_key = client.get_signing_key_from_jwt(token)
        except jwt.InvalidTokenError as exc:  # malformed token (cannot parse header/kid)
            raise AuthError(type(exc).__name__) from exc
        except (jwt.PyJWKClientError, OSError) as exc:  # JWKS unreachable / no key / network
            raise IdentityUnavailable(type(exc).__name__) from exc

        try:
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.InvalidTokenError as exc:  # expired / bad-sig / aud / iss / missing claim
            raise AuthError(type(exc).__name__) from exc

        role = claims.get(self._role_claim)
        return role.strip() if isinstance(role, str) else ""
