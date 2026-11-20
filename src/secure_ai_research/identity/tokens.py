"""Stdlib HS256 JWT verification (Phase 5, Slice 4).

No third-party dependency: the default ``local`` identity mode verifies a symmetric HS256
signature with :mod:`hmac`/:mod:`hashlib`, so even offline the role is authenticated, not
self-asserted. (RS256/OIDC lives behind the opt-in ``[oidc]`` extra, in ``oidc.py``.) The
verifier is deliberately strict and fail-closed — every malformed, forged, or expired token
raises :class:`AuthError`, never a bare ``ValueError``/``KeyError``/``TypeError``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
from typing import Any

from secure_ai_research.identity.ports import AuthError

# base64url alphabet, at least one char, no padding, no '+'/'/'/whitespace.
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


def _decode_segment(segment: str) -> bytes:
    if not _B64URL.fullmatch(segment):
        raise AuthError("invalid token encoding")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (ValueError, TypeError) as exc:  # pragma: no cover - charset already gated above
        raise AuthError("invalid token encoding") from exc


def _loads_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError are both ValueError
        raise AuthError("invalid token json") from exc
    if not isinstance(value, dict):
        raise AuthError("token segment is not a JSON object")
    return value


def _numeric_claim(payload: dict[str, Any], name: str) -> float | None:
    """Return a finite, non-bool numeric claim as float, or None if absent. Raise on a bad type."""
    if name not in payload:
        return None
    value = payload[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AuthError(f"non-numeric {name}")
    try:
        number = float(value)
    except (OverflowError, ValueError) as exc:  # e.g. exp = 10**400 → int too large for float
        raise AuthError(f"out-of-range {name}") from exc
    if not math.isfinite(number):
        raise AuthError(f"non-finite {name}")
    return number


def verify_hs256(token: str, secret: str, *, now: float) -> dict[str, Any]:
    """Verify an HS256 JWT and return its claims, or raise :class:`AuthError`.

    Pins ``alg`` to HS256 (rejecting ``none``/RS256 and any ``crit`` header), checks the HMAC in
    constant time, and requires a numeric, finite, non-expired ``exp``; ``nbf``/``iat`` are
    honoured with zero leeway when present. ``now`` is injected for determinism.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("token must have three segments")
    header_b64, payload_b64, sig_b64 = parts
    # Charset-gate every segment up front, before the HMAC encodes "header.payload" as ASCII.
    # Starlette decodes request headers as latin-1, so an attacker can put a byte >=0x80 in a
    # segment; without this gate that would raise UnicodeEncodeError at signature time (an
    # unauthenticated-reachable 500), not a fail-closed AuthError.
    for segment in parts:
        if not _B64URL.fullmatch(segment):
            raise AuthError("invalid token encoding")

    header = _loads_object(_decode_segment(header_b64))
    if header.get("alg") != "HS256":
        raise AuthError("unsupported alg")
    if "crit" in header:
        raise AuthError("unsupported crit header")

    expected = hmac.new(
        secret.encode("utf-8"), f"{header_b64}.{payload_b64}".encode("ascii"), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected, _decode_segment(sig_b64)):
        raise AuthError("bad signature")

    payload = _loads_object(_decode_segment(payload_b64))

    exp = _numeric_claim(payload, "exp")
    if exp is None:
        raise AuthError("missing exp")
    if exp <= now:
        raise AuthError("token expired")
    nbf = _numeric_claim(payload, "nbf")
    if nbf is not None and now < nbf:
        raise AuthError("token not yet valid")
    iat = _numeric_claim(payload, "iat")
    if iat is not None and iat > now:
        raise AuthError("token issued in the future")

    return payload
