from fastapi.testclient import TestClient

from secure_ai_research.api.main import app

client = TestClient(app)


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


def test_research_cve_501():
    resp = client.get("/research/cve/CVE-2026-0001")
    assert resp.status_code == 501
    assert "Phase 2" in resp.json()["detail"]


def test_research_search_501():
    resp = client.post("/research/search", json={"query": "ransomware"})
    assert resp.status_code == 501
