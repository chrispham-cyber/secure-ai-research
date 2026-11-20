"""Live Keycloak OIDC integration (Phase 5, Slice 4, Task 7) — ``-m integration`` only.

Proves :class:`OidcIdentityProvider` verifies real RS256 tokens from a live Keycloak realm:
per-user role claims (not hardcoded in a mapper), end-to-end route authorization in ``oidc`` mode,
and fail-closed on a tampered token / unreachable JWKS. ``jwt`` is never imported at module top
(the provider imports it lazily), so the hermetic default suite *collects* this file but never
imports pyjwt; ``_require_keycloak`` then skips cleanly when the extra or the server is absent.

Prereqs (skipped cleanly if absent):
    docker compose --profile identity up -d keycloak
    ./.venv/bin/pip install -e '.[oidc]'
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from importlib.resources import files

import pytest
from fastapi.testclient import TestClient

from secure_ai_research.api.deps import get_identity_provider, get_service
from secure_ai_research.api.main import app
from secure_ai_research.identity.oidc import OidcIdentityProvider
from secure_ai_research.identity.ports import AuthError, IdentityUnavailable
from secure_ai_research.ingestion import nvd
from secure_ai_research.research_service import ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore

pytestmark = pytest.mark.integration

BASE = "http://localhost:8080/realms/sair"
ISSUER = BASE
JWKS_URL = f"{BASE}/protocol/openid-connect/certs"
TOKEN_URL = f"{BASE}/protocol/openid-connect/token"
CONFIG_URL = f"{BASE}/.well-known/openid-configuration"
AUDIENCE = "sair-api"


def _require_keycloak() -> None:
    """Skip cleanly unless the ``[oidc]`` extra is installed AND the realm's OIDC config answers."""
    pytest.importorskip("jwt")
    try:
        with urllib.request.urlopen(CONFIG_URL, timeout=3) as resp:  # noqa: S310 (loopback, dev)
            if resp.status != 200:
                pytest.skip(f"Keycloak realm not ready (HTTP {resp.status})")
    except (urllib.error.URLError, OSError) as exc:
        pytest.skip(f"Keycloak unreachable at {CONFIG_URL}: {exc}")


def _token(user: str, pw: str = "pw") -> str:
    """Direct-access (password) grant against live Keycloak → access_token string."""
    data = urllib.parse.urlencode(
        {"grant_type": "password", "client_id": AUDIENCE, "username": user, "password": pw}
    ).encode("ascii")
    req = urllib.request.Request(TOKEN_URL, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (loopback, dev)
        return json.load(resp)["access_token"]


def _service(tmp_path) -> ResearchService:
    raw = files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()
    svc = ResearchService(
        HashingEmbedder(), InMemoryVectorStore(), authorize, tmp_path / "audit.jsonl"
    )
    svc.index(nvd.load(raw))
    return svc


def test_senior_token_resolves_senior_role():
    _require_keycloak()
    p = OidcIdentityProvider(ISSUER, JWKS_URL, AUDIENCE)
    role = p.identify(authorization=f"Bearer {_token('senior-test')}", x_role="")
    assert role == "senior_analyst"


def test_per_user_claim_is_not_hardcoded():
    # Same mapper, different user → different role: proves the claim is the user's own role,
    # not a value baked into the realm export.
    _require_keycloak()
    p = OidcIdentityProvider(ISSUER, JWKS_URL, AUDIENCE)
    role = p.identify(authorization=f"Bearer {_token('analyst-test')}", x_role="")
    assert role == "research_analyst"


def test_end_to_end_route_in_oidc_mode_authorizes(tmp_path):
    _require_keycloak()
    provider = OidcIdentityProvider(ISSUER, JWKS_URL, AUDIENCE)
    svc = _service(tmp_path)
    app.dependency_overrides[get_identity_provider] = lambda: provider
    app.dependency_overrides[get_service] = lambda: svc
    try:
        resp = TestClient(app).get(
            "/research/cve/CVE-2099-0001",
            headers={"Authorization": f"Bearer {_token('senior-test')}"},
        )
        assert resp.status_code == 200
        assert resp.json()["citations"][0]["document_id"] == "CVE-2099-0001"
    finally:
        app.dependency_overrides.clear()


def test_tampered_token_is_401():
    _require_keycloak()
    p = OidcIdentityProvider(ISSUER, JWKS_URL, AUDIENCE)
    tampered = _token("senior-test")[:-3] + "zzz"
    with pytest.raises(AuthError):
        p.identify(authorization=f"Bearer {tampered}", x_role="")


def test_unreachable_jwks_is_identity_unavailable():
    _require_keycloak()
    p = OidcIdentityProvider(ISSUER, "http://127.0.0.1:1/jwks", AUDIENCE)
    with pytest.raises(IdentityUnavailable):
        p.identify(authorization=f"Bearer {_token('senior-test')}", x_role="")
