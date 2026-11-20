"""The API surfaces the configured generator end-to-end (Phase 5, Slice 1a, Task 4).

Hermetic: the default path returns the deterministic golden answer (no Ollama), an injected
generator's grounded line reaches the HTTP response, and selecting ``ollama`` via settings makes
``get_service`` build an OllamaGenerator-backed service (constructed lazily — no network).
"""

from __future__ import annotations

from importlib.resources import files

import pytest
from fastapi.testclient import TestClient

from _authtokens import mint_hs256, pinned_local_identity
from secure_ai_research import config
from secure_ai_research.api.deps import get_identity_provider, get_service
from secure_ai_research.api.main import app
from secure_ai_research.generation.ollama import OllamaGenerator
from secure_ai_research.ingestion import nvd
from secure_ai_research.research_service import ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore

client = TestClient(app)

_GOLDEN_ANSWER = (
    "# Research report: Correlate CVE-2099-0001 against public sources\n\n"
    "CVE-2099-0001 is a synthetic SQL injection in the example login form that lets an "
    "unauthenticated attacker read arbitrary rows from the accounts database. This record "
    "is fictional test data. [CVE-2099-0001]\n\n"
    "Sources: CVE-2099-0001"
)
_FAKE_LINE = "CVE-2099-0001 synthetic SQL injection summary [CVE-2099-0001]"


class _RecordingGen:
    def generate(self, prompt, passages) -> str:
        return _FAKE_LINE


def _svc(tmp_path, generator=None) -> ResearchService:
    raw = files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()
    svc = ResearchService(
        HashingEmbedder(),
        InMemoryVectorStore(),
        authorize,
        tmp_path / "audit.jsonl",
        generator=generator,
    )
    svc.index(nvd.load(raw))
    return svc


def _bearer(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {mint_hs256(role)}"}


@pytest.fixture(autouse=True)
def _pin_identity():
    app.dependency_overrides[get_identity_provider] = pinned_local_identity
    yield
    app.dependency_overrides.pop(get_identity_provider, None)


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


def test_api_default_answer_unchanged(tmp_path):
    app.dependency_overrides[get_service] = lambda: _svc(tmp_path)
    resp = client.get("/research/cve/CVE-2099-0001", headers=_bearer("research_analyst"))
    assert resp.status_code == 200
    assert resp.json()["answer"] == _GOLDEN_ANSWER


def test_api_uses_injected_generator(tmp_path):
    app.dependency_overrides[get_service] = lambda: _svc(tmp_path, _RecordingGen())
    resp = client.get("/research/cve/CVE-2099-0001", headers=_bearer("research_analyst"))
    assert resp.status_code == 200
    assert _FAKE_LINE in resp.json()["answer"]


def test_deps_builds_ollama_generator_when_configured(monkeypatch):
    monkeypatch.setenv("SAIR_GENERATOR", "ollama")
    config.get_settings.cache_clear()
    get_service.cache_clear()
    try:
        svc = get_service()
        assert isinstance(svc._generator, OllamaGenerator)
    finally:
        config.get_settings.cache_clear()
        get_service.cache_clear()
