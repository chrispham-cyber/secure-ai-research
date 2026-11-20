"""Factory selecting the IdentityProvider from Settings — fail-closed by construction (Slice 4).

:func:`make_identity_provider` never raises: an operational/config failure (the placeholder dev
secret with no opt-in, a missing ``[oidc]`` extra, an unreachable JWKS) surfaces at ``identify()``
time as :class:`IdentityUnavailable` → 503, so a ``Depends``-injected provider is both
test-overridable and never an unhandled 500. The insecure mode and the fail-closed local mode each
log a ``WARNING`` when selected (threat T1 self-announcing, spec §6).
"""

from __future__ import annotations

import logging

from secure_ai_research.config import Settings
from secure_ai_research.identity.oidc import OidcIdentityProvider
from secure_ai_research.identity.ports import IdentityProvider, IdentityUnavailable
from secure_ai_research.identity.providers import (
    InsecureIdentityProvider,
    LocalTokenIdentityProvider,
)

logger = logging.getLogger(__name__)

# Must match Settings.auth_dev_secret's default. The placeholder — and any secret shorter than
# _MIN_SECRET_LEN — fails closed unless SAIR_AUTH_ALLOW_DEV_SECRET=1. (The Settings() default-path
# test is the drift guard: it builds with this exact default and asserts fail-closed.)
_PLACEHOLDER_SECRET = "dev-insecure-change-me-not-for-production"
_MIN_SECRET_LEN = 16


class _UnavailableProvider:
    """A fail-closed provider: every ``identify()`` raises :class:`IdentityUnavailable` (→ 503)."""

    def __init__(self, reason: str) -> None:
        self._reason = reason

    def identify(self, *, authorization: str, x_role: str) -> str:
        raise IdentityUnavailable(self._reason)


def make_identity_provider(settings: Settings) -> IdentityProvider:
    """Build the IdentityProvider for ``settings.auth``. Never raises (fails closed at identify)."""
    if settings.auth == "insecure":
        logger.warning(
            "SAIR_AUTH=insecure: the spoofable X-Role header is trusted verbatim; "
            "do not use outside local development."
        )
        return InsecureIdentityProvider()

    if settings.auth == "oidc":
        return OidcIdentityProvider(
            settings.oidc_issuer,
            settings.oidc_jwks_url,
            settings.oidc_audience,
            role_claim=settings.auth_role_claim,
            timeout=settings.oidc_timeout,
        )

    # local (default)
    secret = settings.auth_dev_secret
    is_weak = secret == _PLACEHOLDER_SECRET or len(secret) < _MIN_SECRET_LEN
    if is_weak and not settings.auth_allow_dev_secret:
        logger.warning(
            "SAIR_AUTH=local is using the insecure placeholder/short dev secret and is "
            "FAIL-CLOSED (every request -> 503). Set SAIR_AUTH_DEV_SECRET to a strong secret, "
            "or SAIR_AUTH_ALLOW_DEV_SECRET=1 to allow the dev secret explicitly."
        )
        return _UnavailableProvider(
            "local auth secret is the insecure placeholder; set SAIR_AUTH_DEV_SECRET "
            "or SAIR_AUTH_ALLOW_DEV_SECRET=1"
        )
    return LocalTokenIdentityProvider(secret, role_claim=settings.auth_role_claim)
