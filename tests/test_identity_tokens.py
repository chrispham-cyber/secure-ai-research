"""Unit tests for the stdlib HS256 verifier (Phase 5 Slice 4, Task 1).

One test per spec §5.3 rule. Both mint and verify are pinned to a fixed ``NOW`` so the exp
checks are deterministic. Covers Review Focus #1 (alg-confusion) and #2 (non-object payload).
"""

from __future__ import annotations

import pytest

from _authtokens import TEST_SECRET, mint_hs256, raw_token_with_header, raw_token_with_payload
from secure_ai_research.identity.ports import AuthError
from secure_ai_research.identity.tokens import verify_hs256

NOW = 1_000_000.0


def test_valid_token_returns_claims():
    tok = mint_hs256("senior_analyst", now=NOW)
    claims = verify_hs256(tok, TEST_SECRET, now=NOW)
    assert claims["role"] == "senior_analyst"


def test_rejects_bad_signature():
    tok = mint_hs256(sign_with="wrong-secret-0123456789", now=NOW)
    with pytest.raises(AuthError):
        verify_hs256(tok, TEST_SECRET, now=NOW)


def test_rejects_alg_none():
    tok = mint_hs256(alg="none", now=NOW)
    with pytest.raises(AuthError):
        verify_hs256(tok, TEST_SECRET, now=NOW)


def test_rejects_alg_rs256():  # alg-confusion: an HS verifier must not honour an RS header
    tok = mint_hs256(alg="RS256", now=NOW)
    with pytest.raises(AuthError):
        verify_hs256(tok, TEST_SECRET, now=NOW)


def test_requires_exp():
    tok = mint_hs256(include_exp=False, now=NOW)
    with pytest.raises(AuthError):
        verify_hs256(tok, TEST_SECRET, now=NOW)


def test_rejects_expired():
    tok = mint_hs256(exp_delta=-1.0, now=NOW)
    with pytest.raises(AuthError):
        verify_hs256(tok, TEST_SECRET, now=NOW)


def test_rejects_non_numeric_exp():  # exp as bool / str / NaN / inf
    for bad in (True, "soon", float("nan"), float("inf")):
        tok = mint_hs256(extra={"exp": bad}, include_exp=False, now=NOW)
        with pytest.raises(AuthError):
            verify_hs256(tok, TEST_SECRET, now=NOW)


def test_rejects_non_object_payload():  # payload is a JSON list, not an object
    with pytest.raises(AuthError):
        verify_hs256(raw_token_with_payload(b"[]"), TEST_SECRET, now=NOW)


def test_rejects_non_json_segment():  # payload is not valid JSON at all
    with pytest.raises(AuthError):
        verify_hs256(raw_token_with_payload(b"\xff\xff"), TEST_SECRET, now=NOW)


def test_rejects_standard_base64_chars():  # '+' / '/' are not base64url
    with pytest.raises(AuthError):
        verify_hs256("ab+/.ab+/.sig", TEST_SECRET, now=NOW)


def test_rejects_wrong_segment_count():
    with pytest.raises(AuthError):
        verify_hs256("only.two", TEST_SECRET, now=NOW)


def test_rejects_crit_header():
    tok = raw_token_with_header({"alg": "HS256", "typ": "JWT", "crit": ["x"]})
    with pytest.raises(AuthError):
        verify_hs256(tok, TEST_SECRET, now=NOW)
