"""Tests for the identity factory: mode selection + fail-closed dev-secret gate (Slice 4, Task 4).

Covers Review Focus #5 (the placeholder-secret default fails closed; the opt-in re-enables it).
"""

from __future__ import annotations

import pytest

from secure_ai_research.config import Settings
from secure_ai_research.identity.factory import make_identity_provider
from secure_ai_research.identity.oidc import OidcIdentityProvider
from secure_ai_research.identity.ports import IdentityUnavailable
from secure_ai_research.identity.providers import (
    InsecureIdentityProvider,
    LocalTokenIdentityProvider,
)


def test_default_is_local_provider():
    settings = Settings(auth_allow_dev_secret=True)  # opt-in so the dev secret is allowed
    assert isinstance(make_identity_provider(settings), LocalTokenIdentityProvider)


def test_placeholder_secret_fails_closed():
    provider = make_identity_provider(Settings())  # placeholder secret, no opt-in
    with pytest.raises(IdentityUnavailable):
        provider.identify(authorization="Bearer x", x_role="")


def test_short_secret_fails_closed():
    provider = make_identity_provider(Settings(auth_dev_secret="short"))
    with pytest.raises(IdentityUnavailable):
        provider.identify(authorization="Bearer x", x_role="")


def test_opt_in_allows_dev_secret():
    settings = Settings(auth_allow_dev_secret=True)
    assert isinstance(make_identity_provider(settings), LocalTokenIdentityProvider)


def test_strong_secret_needs_no_opt_in():
    settings = Settings(auth_dev_secret="a-strong-secret-0123456789")
    assert isinstance(make_identity_provider(settings), LocalTokenIdentityProvider)


def test_oidc_mode_builds_oidc_provider():
    assert isinstance(make_identity_provider(Settings(auth="oidc")), OidcIdentityProvider)


def test_insecure_mode_warns(caplog):
    with caplog.at_level("WARNING"):
        provider = make_identity_provider(Settings(auth="insecure"))
    assert isinstance(provider, InsecureIdentityProvider)
    assert any("insecure" in r.message.lower() for r in caplog.records)
