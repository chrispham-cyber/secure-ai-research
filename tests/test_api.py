from datetime import date
from importlib.resources import files

import pytest
from fastapi.testclient import TestClient

from secure_ai_research.api.deps import get_service
from secure_ai_research.api.main import app
from secure_ai_research.audit.record import read_records
from secure_ai_research.config import get_settings
from secure_ai_research.generation.ports import GeneratorError
from secure_ai_research.ingestion import nvd
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import Classification, DocumentType, ResearchDocument
from secure_ai_research.ingestion.source import CveNotFound, CveUnavailable
from secure_ai_research.research_service import ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore

client = TestClient(app)


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


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


# --- fetch-on-miss endpoint (Phase-2 fetch-on-miss slice) ---


def _one_doc(cve_id: str = "CVE-2099-7777") -> IngestedDocument:
    doc = ResearchDocument(
        document_id=cve_id,
        source="NVD",
        document_type=DocumentType.VULNERABILITY,
        classification=Classification.PUBLIC,
        created_at=date(2099, 1, 1),
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",  # type: ignore[arg-type]
        integrity_hash="sha256:" + "0" * 64,
    )
    return IngestedDocument(doc, f"{cve_id} remote code execution in the widget parser")


class _FakeFetch:
    def __init__(self, docs=None, exc=None):
        self.docs = docs
        self.exc = exc
        self.calls = 0

    def __call__(self, cve_id):
        self.calls += 1
        if self.exc:
            raise self.exc
        return self.docs


def _override_fetch_service(tmp_path, fetch):
    raw = files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()
    svc = ResearchService(
        HashingEmbedder(),
        InMemoryVectorStore(),
        authorize,
        tmp_path / "audit.jsonl",
        fetch_missing=fetch,
    )
    svc.index(nvd.load(raw))
    app.dependency_overrides[get_service] = lambda: svc
    return svc


def test_fetch_on_miss_is_200_with_citation(tmp_path):
    _override_fetch_service(tmp_path, _FakeFetch(docs=[_one_doc("CVE-2099-7777")]))
    resp = client.get("/research/cve/CVE-2099-7777", headers={"X-Role": "senior_analyst"})
    assert resp.status_code == 200
    assert any(c["document_id"] == "CVE-2099-7777" for c in resp.json()["citations"])


def test_fetch_absent_is_404(tmp_path):
    _override_fetch_service(tmp_path, _FakeFetch(exc=CveNotFound("absent")))
    resp = client.get("/research/cve/CVE-2099-7777", headers={"X-Role": "senior_analyst"})
    assert resp.status_code == 404


def test_fetch_unavailable_is_503(tmp_path):
    _override_fetch_service(tmp_path, _FakeFetch(exc=CveUnavailable("down")))
    resp = client.get("/research/cve/CVE-2099-7777", headers={"X-Role": "senior_analyst"})
    assert resp.status_code == 503
    assert resp.json()["detail"] == "upstream source unavailable"


def test_unknown_cve_without_fetch_is_404(tmp_path):
    _override_fetch_service(tmp_path, None)
    resp = client.get("/research/cve/CVE-2099-7777", headers={"X-Role": "research_analyst"})
    assert resp.status_code == 404


def test_unauthorized_never_fetches(tmp_path):
    spy = _FakeFetch(docs=[_one_doc("CVE-2099-7777")])
    _override_fetch_service(tmp_path, spy)
    resp = client.get("/research/cve/CVE-2099-7777", headers={"X-Role": "security_auditor"})
    assert resp.status_code == 403
    assert spy.calls == 0


def test_get_service_offline_by_default(monkeypatch):
    # Setting OFF (default): the process service has no fetch callable → no network path.
    monkeypatch.delenv("SAIR_ALLOW_LIVE_FETCH", raising=False)
    get_settings.cache_clear()
    get_service.cache_clear()
    try:
        assert get_service()._fetch_missing is None
    finally:
        get_service.cache_clear()
        get_settings.cache_clear()


def test_get_service_wires_fetch_when_enabled(monkeypatch):
    monkeypatch.setenv("SAIR_ALLOW_LIVE_FETCH", "true")
    get_settings.cache_clear()
    get_service.cache_clear()
    try:
        assert get_service()._fetch_missing is not None
    finally:
        get_service.cache_clear()
        get_settings.cache_clear()


# --- fetch-on-miss cache-fault handling (Review Focus #5, via the real wired deps) ---


def _enable_live_fetch(monkeypatch, tmp_path):
    # Point the real (non-overridden) get_service at a live-fetch build with tmp cache +
    # audit paths, then clear the caches so the next build reads this env.
    monkeypatch.setenv("SAIR_ALLOW_LIVE_FETCH", "true")
    monkeypatch.setenv("SAIR_NVD_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    get_settings.cache_clear()
    get_service.cache_clear()


def test_corrupt_cache_content_is_503(tmp_path, monkeypatch):
    # A cache *hit* on a file with an unparseable body: a hit is served without
    # re-validation, so the deps closure re-parses it → CveUnavailable → 503 + one audit
    # record. Hermetic: the hit means NVD is never contacted.
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "CVE-2099-7777.json").write_bytes(b"{ not valid json")
    _enable_live_fetch(monkeypatch, tmp_path)
    try:
        resp = client.get("/research/cve/CVE-2099-7777", headers={"X-Role": "senior_analyst"})
        assert resp.status_code == 503
        assert resp.json()["detail"] == "upstream source unavailable"
        assert len(read_records(tmp_path / "audit.jsonl")) == 1
    finally:
        get_service.cache_clear()
        get_settings.cache_clear()


def test_unreadable_cache_entry_is_503_not_500(tmp_path, monkeypatch):
    # A cache path that cannot be read as a file (here a directory) raises OSError from the
    # cache layer, which escapes the deps closure's narrow try — the service backstop must
    # still turn it into 503 + one audit record, never an unhandled 500 with no audit trail.
    (tmp_path / "cache" / "CVE-2099-7777.json").mkdir(parents=True)
    _enable_live_fetch(monkeypatch, tmp_path)
    try:
        resp = client.get("/research/cve/CVE-2099-7777", headers={"X-Role": "senior_analyst"})
        assert resp.status_code == 503
        assert len(read_records(tmp_path / "audit.jsonl")) == 1
    finally:
        get_service.cache_clear()
        get_settings.cache_clear()


# --- ATT&CK technique endpoint (Phase-2 ATT&CK endpoint slice) ---


def _technique_doc(tid="T1059"):
    doc = ResearchDocument(
        document_id=tid,
        source="MITRE ATT&CK",
        document_type=DocumentType.TECHNIQUE,
        classification=Classification.PUBLIC,
        created_at=date(2017, 5, 31),
        source_url=f"https://attack.mitre.org/techniques/{tid}/",  # type: ignore[arg-type]
        integrity_hash="sha256:" + "0" * 64,
    )
    return IngestedDocument(doc, f"{tid}: adversaries abuse command and scripting interpreters")


def _override_tech_service(tmp_path, tid="T1059"):
    svc = ResearchService(
        HashingEmbedder(), InMemoryVectorStore(), authorize, tmp_path / "audit.jsonl"
    )
    svc.index([_technique_doc(tid)])
    app.dependency_overrides[get_service] = lambda: svc
    return svc


def test_attack_permitted_returns_cited_answer(tmp_path):
    _override_tech_service(tmp_path, "T1059")
    resp = client.get("/research/attack/T1059", headers={"X-Role": "research_analyst"})
    assert resp.status_code == 200
    assert any(c["document_id"] == "T1059" for c in resp.json()["citations"])
    assert resp.json()["research_id"]


def test_attack_subtechnique_200(tmp_path):
    _override_tech_service(tmp_path, "T1059.001")
    resp = client.get("/research/attack/T1059.001", headers={"X-Role": "research_analyst"})
    assert resp.status_code == 200


def test_attack_missing_role_denied(tmp_path):
    _override_tech_service(tmp_path)
    assert client.get("/research/attack/T1059").status_code == 403


def test_attack_absent_is_404(tmp_path):
    _override_tech_service(tmp_path)
    resp = client.get("/research/attack/T9999", headers={"X-Role": "research_analyst"})
    assert resp.status_code == 404


@pytest.mark.parametrize("bad", ["TA0001", "T123", "t1059", "1059", "T1059.1"])
def test_attack_malformed_is_422(tmp_path, bad):
    _override_tech_service(tmp_path)
    resp = client.get(f"/research/attack/{bad}", headers={"X-Role": "research_analyst"})
    assert resp.status_code == 422


def test_deps_indexes_attack_fixture(tmp_path, monkeypatch):
    # Drive the real (non-overridden) get_service: the packaged ATT&CK fixture must be
    # indexed at startup so a real technique answers through the live wiring.
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    get_settings.cache_clear()
    get_service.cache_clear()
    try:
        resp = client.get("/research/attack/T1059", headers={"X-Role": "research_analyst"})
        assert resp.status_code == 200
        assert any(c["document_id"] == "T1059" for c in resp.json()["citations"])
    finally:
        get_service.cache_clear()
        get_settings.cache_clear()


def test_deps_deprecated_technique_is_404(tmp_path, monkeypatch):
    # T1064 (Scripting) is x_mitre_deprecated in current ATT&CK; the loader skips it, so it
    # is absent from the corpus and answers 404 — the skip path exercised with real data.
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    get_settings.cache_clear()
    get_service.cache_clear()
    try:
        resp = client.get("/research/attack/T1064", headers={"X-Role": "research_analyst"})
        assert resp.status_code == 404
    finally:
        get_service.cache_clear()
        get_settings.cache_clear()


def test_deps_kev_entry_is_searchable(tmp_path, monkeypatch):
    # Drive the real (non-overridden) get_service: the packaged CISA KEV fixture must be
    # indexed at startup so a KEV CVE surfaces through the live /research/search wiring.
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    get_settings.cache_clear()
    get_service.cache_clear()
    try:
        resp = client.post(
            "/research/search",
            json={"query": "CVE-2021-44228"},
            headers={"X-Role": "research_analyst"},
        )
        assert resp.status_code == 200
        assert any(r["document_id"] == "KEV-CVE-2021-44228" for r in resp.json()["results"])
    finally:
        get_service.cache_clear()
        get_settings.cache_clear()


def test_deps_sigma_rule_is_searchable(tmp_path, monkeypatch):
    # Drive the real (non-overridden) get_service: the packaged SigmaHQ fixture must be indexed
    # at startup so a technique search surfaces the detection rule (SIGMA-… document) beside the
    # ATT&CK document — the detection↔technique correlation this slice adds.
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    get_settings.cache_clear()
    get_service.cache_clear()
    try:
        resp = client.post(
            "/research/search",
            json={"query": "T1059"},
            headers={"X-Role": "research_analyst"},
        )
        assert resp.status_code == 200
        assert any(r["document_id"].startswith("SIGMA-") for r in resp.json()["results"])
    finally:
        get_service.cache_clear()
        get_settings.cache_clear()


# --- POST /research/search (Phase-2 search endpoint slice) ---


def _override_search_service(tmp_path, generator=None):
    audit = tmp_path / "audit.jsonl"
    svc = ResearchService(
        HashingEmbedder(), InMemoryVectorStore(), authorize, audit, generator=generator
    )
    svc.index(
        [
            IngestedDocument(
                ResearchDocument(
                    document_id="CVE-2099-0001",
                    source="NVD",
                    document_type=DocumentType.VULNERABILITY,
                    classification=Classification.PUBLIC,
                    created_at=date(2099, 1, 1),
                    source_url="https://nvd.nist.gov/vuln/detail/CVE-2099-0001",  # type: ignore[arg-type]
                    integrity_hash="sha256:" + "0" * 64,
                ),
                "widget widget widget",
            ),
            IngestedDocument(
                ResearchDocument(
                    document_id="T1059",
                    source="MITRE ATT&CK",
                    document_type=DocumentType.TECHNIQUE,
                    classification=Classification.PUBLIC,
                    created_at=date(2017, 5, 31),
                    source_url="https://attack.mitre.org/techniques/T1059/",  # type: ignore[arg-type]
                    integrity_hash="sha256:" + "0" * 64,
                ),
                "widget alpha",
            ),
        ]
    )
    app.dependency_overrides[get_service] = lambda: svc
    return audit


def test_search_200_has_rank_not_score(tmp_path):
    _override_search_service(tmp_path)
    resp = client.post(
        "/research/search", json={"query": "widget"}, headers={"X-Role": "research_analyst"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] == "widget"
    assert body["count"] == len(body["results"])
    assert body["research_id"]
    first = body["results"][0]
    assert first["rank"] == 1 and first["document_id"] == "CVE-2099-0001" and "passage" in first
    assert "source_url" in first and "score" not in first


def test_search_missing_role_denied(tmp_path):
    _override_search_service(tmp_path)
    assert client.post("/research/search", json={"query": "widget"}).status_code == 403


def test_search_blank_query_422_no_audit(tmp_path):
    audit = _override_search_service(tmp_path)
    resp = client.post(
        "/research/search", json={"query": "   "}, headers={"X-Role": "research_analyst"}
    )
    assert resp.status_code == 422
    assert not audit.exists()  # validation rejected before the handler → zero audit records


def test_search_oversized_query_422(tmp_path):
    _override_search_service(tmp_path)
    resp = client.post(
        "/research/search", json={"query": "x" * 513}, headers={"X-Role": "research_analyst"}
    )
    assert resp.status_code == 422


@pytest.mark.parametrize("bad_limit", [0, 21])
def test_search_limit_out_of_range_422(tmp_path, bad_limit):
    _override_search_service(tmp_path)
    resp = client.post(
        "/research/search",
        json={"query": "widget", "limit": bad_limit},
        headers={"X-Role": "research_analyst"},
    )
    assert resp.status_code == 422


# --- POST /research/ask (Slice 1b free-form QA) ---
# Reuses the search-route corpus ("widget …" docs) so the query "widget" retrieves real hits
# and the injected generator is actually invoked (the 503 path needs a non-empty retrieval).


class _AskRecordingGen:
    """Grounded fake: one line citing the retrieved CVE, so build_report keeps it."""

    def generate(self, prompt, passages) -> str:
        return "widget widget widget [CVE-2099-0001]"


class _AskFailingGen:
    def generate(self, prompt, passages) -> str:
        raise GeneratorError("boom")


def test_ask_200_returns_answer_and_citations(tmp_path):
    _override_search_service(tmp_path, _AskRecordingGen())
    r = client.post(
        "/research/ask", json={"query": "widget"}, headers={"X-Role": "research_analyst"}
    )
    assert r.status_code == 200
    body = r.json()
    assert "answer" in body and "citations" in body and "research_id" in body
    assert body["citations"]
    assert set(body["citations"][0]) == {"document_id", "source_url", "passage"}


def test_ask_missing_role_is_403(tmp_path):
    _override_search_service(tmp_path)
    r = client.post("/research/ask", json={"query": "widget"})
    assert r.status_code == 403
    assert r.json()["detail"] == "role not authorized"


def test_ask_generator_failure_is_503(tmp_path):
    _override_search_service(tmp_path, _AskFailingGen())
    r = client.post(
        "/research/ask", json={"query": "widget"}, headers={"X-Role": "research_analyst"}
    )
    assert r.status_code == 503
    assert r.json()["detail"] == "upstream source unavailable"


def test_ask_empty_query_is_422(tmp_path):
    audit = _override_search_service(tmp_path)
    r = client.post(
        "/research/ask", json={"query": "   "}, headers={"X-Role": "research_analyst"}
    )
    assert r.status_code == 422
    assert not audit.exists()  # validation rejected before the handler → zero audit records
