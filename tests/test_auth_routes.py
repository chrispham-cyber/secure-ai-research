"""Route-level auth tests for the verified-token get_role dependency (Slice 4, Task 5).

These drive the REAL identity path (get_identity_provider is NOT overridden) via env + cache
clears, so they exercise the factory, the providers, and the 401/503 boundary end-to-end.

Review Focus coverage: #3 (no-token → 401, zero audit, and 401-before-422), #4 (IdP/extra
unavailable → 503), #5 (placeholder default → 503).
"""

from __future__ import annotations

from importlib.resources import files

import pytest
from fastapi.testclient import TestClient

from _authtokens import TEST_SECRET, mint_hs256
from secure_ai_research.api.deps import get_identity_provider, get_service
from secure_ai_research.api.main import app
from secure_ai_research.config import get_settings
from secure_ai_research.ingestion import nvd
from secure_ai_research.research_service import ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore

client = TestClient(app)


def _reload_auth() -> None:
    get_settings.cache_clear()
    get_identity_provider.cache_clear()


def bearer(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {mint_hs256(role)}"}


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    app.dependency_overrides.clear()
    _reload_auth()


@pytest.fixture
def service(tmp_path):
    """Temp-audit service override; yields the audit path for 0/1-record assertions."""
    audit = tmp_path / "audit.jsonl"
    raw = files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit)
    svc.index(nvd.load(raw))
    app.dependency_overrides[get_service] = lambda: svc
    return audit


@pytest.fixture
def local_auth(monkeypatch):
    """Real local mode with the test secret explicitly allowed."""
    monkeypatch.setenv("SAIR_AUTH", "local")
    monkeypatch.setenv("SAIR_AUTH_ALLOW_DEV_SECRET", "1")
    monkeypatch.setenv("SAIR_AUTH_DEV_SECRET", TEST_SECRET)
    _reload_auth()
    yield


def test_token_authorizes(service, local_auth):
    r = client.get("/research/cve/CVE-2099-0001", headers=bearer("research_analyst"))
    assert r.status_code == 200


def test_no_token_is_401(service, local_auth):
    r = client.get("/research/cve/CVE-2099-0001")
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"] == "Bearer"
    assert r.json() == {"detail": "authentication required"}
    assert not service.exists()  # service fixture yields the audit path → zero records


def test_bad_signature_and_expired_and_alg_none_are_401_byte_identical(service, local_auth):
    bodies = set()
    for tok in (
        mint_hs256(sign_with="nope-0123456789abc"),
        mint_hs256(exp_delta=-1),
        mint_hs256(alg="none"),
    ):
        r = client.get("/research/cve/CVE-2099-0001", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 401
        bodies.add(r.text)
    assert len(bodies) == 1  # no auth-failure-reason oracle


def test_unauthorized_role_token_is_403(service, local_auth):
    r = client.get("/research/cve/CVE-2099-0001", headers=bearer("security_auditor"))
    assert r.status_code == 403


def test_malformed_body_without_token_is_401(service, local_auth):  # 401 fires before 422
    r = client.post("/research/search", json={"query": "   "})
    assert r.status_code == 401


def test_fail_closed_default_is_503(service, monkeypatch):
    monkeypatch.delenv("SAIR_AUTH_ALLOW_DEV_SECRET", raising=False)
    monkeypatch.setenv("SAIR_AUTH_DEV_SECRET", "dev-insecure-change-me-not-for-production")
    _reload_auth()
    r = client.get("/research/cve/CVE-2099-0001", headers=bearer("research_analyst"))
    assert r.status_code == 503


def test_insecure_mode_honors_x_role_and_local_ignores_it(service, monkeypatch):
    monkeypatch.setenv("SAIR_AUTH", "insecure")
    _reload_auth()
    insecure = client.get("/research/cve/CVE-2099-0001", headers={"X-Role": "research_analyst"})
    assert insecure.status_code == 200

    monkeypatch.setenv("SAIR_AUTH", "local")
    monkeypatch.setenv("SAIR_AUTH_ALLOW_DEV_SECRET", "1")
    monkeypatch.setenv("SAIR_AUTH_DEV_SECRET", TEST_SECRET)
    _reload_auth()
    local = client.get("/research/cve/CVE-2099-0001", headers={"X-Role": "research_analyst"})
    assert local.status_code == 401  # local mode ignores X-Role


def test_identity_unavailable_is_503(service, monkeypatch):
    monkeypatch.setenv("SAIR_AUTH", "oidc")
    monkeypatch.setenv("SAIR_OIDC_JWKS_URL", "http://127.0.0.1:1/jwks")
    _reload_auth()
    r = client.get("/research/cve/CVE-2099-0001", headers=bearer("research_analyst"))
    assert r.status_code == 503  # missing [oidc] extra OR unreachable JWKS — both fail closed
