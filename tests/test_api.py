from importlib.resources import files

import pytest
from fastapi.testclient import TestClient

from secure_ai_research.api.deps import get_service
from secure_ai_research.api.main import app
from secure_ai_research.ingestion import nvd
from secure_ai_research.research_service import ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore

client = TestClient(app)


@pytest.fixture
def service(tmp_path):
    raw = files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()
    svc = ResearchService(
        HashingEmbedder(), InMemoryVectorStore(), authorize, tmp_path / "audit.jsonl"
    )
    svc.index(nvd.load(raw))
    app.dependency_overrides[get_service] = lambda: svc
    yield svc
    app.dependency_overrides.clear()


def test_health_ok():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_version_ok_without_weights():
    resp = client.get("/version")
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == "0.1.0"
    assert "example/local-llm" in body["models"]


def test_cve_permitted_returns_cited_answer(service):
    resp = client.get("/research/cve/CVE-2099-0001", headers={"X-Role": "research_analyst"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["answer"]
    assert body["citations"][0]["document_id"] == "CVE-2099-0001"
    assert body["research_id"]


def test_cve_missing_role_denied(service):
    resp = client.get("/research/cve/CVE-2099-0001")
    assert resp.status_code == 403


def test_cve_unknown_role_denied(service):
    resp = client.get("/research/cve/CVE-2099-0001", headers={"X-Role": "security_auditor"})
    assert resp.status_code == 403


def test_cve_absent_is_404(service):
    resp = client.get("/research/cve/CVE-2099-9999", headers={"X-Role": "research_analyst"})
    assert resp.status_code == 404


def test_cve_malformed_is_422(service):
    resp = client.get("/research/cve/not-a-cve", headers={"X-Role": "research_analyst"})
    assert resp.status_code == 422


def test_research_search_501():
    resp = client.post("/research/search", json={"query": "ransomware"})
    assert resp.status_code == 501
