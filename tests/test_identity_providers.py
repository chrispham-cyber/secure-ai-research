"""Tests for the local (HS256) and insecure (X-Role) identity providers (Slice 4, Task 2)."""

from __future__ import annotations

import pytest

from _authtokens import TEST_SECRET, mint_hs256
from secure_ai_research.identity.ports import AuthError
from secure_ai_research.identity.providers import (
    InsecureIdentityProvider,
    LocalTokenIdentityProvider,
)

NOW = 1_000_000.0


def test_local_bearer_token_yields_role():
    p = LocalTokenIdentityProvider(TEST_SECRET, now=lambda: NOW)
    tok = mint_hs256("senior_analyst", now=NOW)
    assert p.identify(authorization=f"Bearer {tok}", x_role="") == "senior_analyst"


def test_local_missing_authorization_raises():
    p = LocalTokenIdentityProvider(TEST_SECRET, now=lambda: NOW)
    # X-Role is ignored in local mode — a missing Authorization is a 401, not a fallback.
    with pytest.raises(AuthError):
        p.identify(authorization="", x_role="research_analyst")


def test_local_non_bearer_scheme_raises():
    p = LocalTokenIdentityProvider(TEST_SECRET, now=lambda: NOW)
    with pytest.raises(AuthError):
        p.identify(authorization="Basic abc", x_role="")


def test_local_blank_or_missing_role_claim_is_empty_string():
    p = LocalTokenIdentityProvider(TEST_SECRET, now=lambda: NOW)
    # A non-string role claim must become "" (never the string "None"); an absent claim → "".
    tok = mint_hs256(role="x", extra={"role": None}, now=NOW)
    assert p.identify(authorization=f"Bearer {tok}", x_role="") == ""


def test_insecure_returns_x_role():
    assert InsecureIdentityProvider().identify(authorization="", x_role=" senior_analyst ") == (
        "senior_analyst"
    )
