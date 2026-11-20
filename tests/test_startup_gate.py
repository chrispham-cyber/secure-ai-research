"""Startup lifespan gate + deps audit wiring (Phase 5, Slice 5, Task 5)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secure_ai_research.api.deps import get_service
from secure_ai_research.api.main import app
from secure_ai_research.audit.signing import verify_chain
from secure_ai_research.config import get_settings
from secure_ai_research.secret.ports import SecretError


@pytest.fixture(autouse=True)
def _reset_caches():
    # Both settings and the service are lru_cached; clear around every test so env mutations
    # below cannot leak a prod-configured settings/service into another test.
    get_settings.cache_clear()
    get_service.cache_clear()
    yield
    get_settings.cache_clear()
    get_service.cache_clear()


def test_startup_dev_is_noop():
    with TestClient(app) as client:  # entering the context runs the lifespan startup
        assert client.get("/health").status_code == 200


def test_startup_prod_weak_secret_refuses_boot(monkeypatch):
    monkeypatch.setenv("SAIR_REQUIRE_STRONG_SECRETS", "true")  # audit key is still the placeholder
    get_settings.cache_clear()
    get_service.cache_clear()
    # lifespan verify_secrets raises SecretError -> TestClient context-enter re-raises it.
    # Asserting the specific type (not a blind Exception) pins the security contract: a weak
    # prod secret fails closed *as a SecretError*, not merely "something broke" (ruff B017).
    with pytest.raises(SecretError):
        with TestClient(app):
            pass


def test_service_from_deps_writes_verifiable_signed_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SAIR_AUDIT_SIGNING_KEY", "wired-key-0123456789abcd")
    get_settings.cache_clear()
    get_service.cache_clear()
    svc = get_service()
    svc.research_cve("CVE-2099-0001", role="senior_analyst")
    v = verify_chain(tmp_path / "audit.jsonl", "wired-key-0123456789abcd")
    assert v.ok and v.count >= 1
