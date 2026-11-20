"""Test-only helpers for minting HS256 JWTs and forged variants — Phase 5 Slice 4.

Imported as a *top-level* module (``from _authtokens import ...``): there is no ``tests``
package, and pytest's default ``prepend`` import mode puts ``tests/`` on ``sys.path``, so this
sibling of the test modules is importable by its bare name.

``mint_hs256`` defaults ``now=None`` → real ``time.time()`` so route-level tokens are valid
against the runtime provider's clock; the verifier unit tests pass an explicit ``now=NOW``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from secure_ai_research.identity.providers import LocalTokenIdentityProvider

# 28 chars — long + non-placeholder, so it passes the Slice-4 dev-secret fail-closed gate.
TEST_SECRET = "test-secret-0123456789abcdef"


def pinned_local_identity() -> LocalTokenIdentityProvider:
    """A LocalTokenIdentityProvider bound to TEST_SECRET, for pinning route tests' identity via
    ``app.dependency_overrides[get_identity_provider] = pinned_local_identity`` (bypasses the
    env-driven factory + fail-closed gate). Uses real ``time.time`` so default-minted tokens are
    valid."""
    return LocalTokenIdentityProvider(TEST_SECRET)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _sign(signing_input: str, secret: str) -> str:
    sig = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return _b64url(sig)


def mint_hs256(
    role: str = "research_analyst",
    *,
    secret: str = TEST_SECRET,
    exp_delta: float = 3600.0,
    now: float | None = None,
    role_claim: str = "role",
    alg: str = "HS256",
    include_exp: bool = True,
    sign_with: str | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Mint an HS256 JWT. Forge knobs: ``alg`` (incl. ``"none"``), ``include_exp=False`` to omit
    exp, ``sign_with`` to sign with a different key, ``extra`` to merge/override claims last."""
    t = time.time() if now is None else now
    header = {"alg": alg, "typ": "JWT"}
    payload: dict[str, Any] = {role_claim: role}
    if include_exp:
        payload["exp"] = t + exp_delta
    if extra:
        payload.update(extra)  # extra overrides role/exp
    head = _b64url(json.dumps(header).encode())
    body = _b64url(json.dumps(payload).encode())
    signing_input = head + "." + body
    if alg == "none":
        return signing_input + "."  # unsecured JWT: empty signature segment
    signing_key = secret if sign_with is None else sign_with
    return signing_input + "." + _sign(signing_input, signing_key)


def raw_token_with_payload(payload_raw: bytes) -> str:
    """A structurally valid, *correctly signed* token whose payload segment is arbitrary bytes.

    Proves the verifier rejects a non-object / non-JSON payload on its own merits, after a valid
    signature — so the rejection is the payload rule, not an incidental signature mismatch.
    """
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(payload_raw)
    signing_input = header + "." + payload
    return signing_input + "." + _sign(signing_input, TEST_SECRET)


def raw_token_with_header(header: dict[str, Any]) -> str:
    """A correctly signed token with an arbitrary header (e.g. a ``crit`` member)."""
    h = _b64url(json.dumps(header).encode())
    p = _b64url(json.dumps({"role": "research_analyst", "exp": time.time() + 3600}).encode())
    signing_input = h + "." + p
    return signing_input + "." + _sign(signing_input, TEST_SECRET)
