"""Live NVD fetch — excluded from the default suite and CI (``-m "not integration"``).

Run explicitly with ``.venv/bin/python -m pytest -m integration``. Keyless; skips
(does not fail) when NVD is unreachable or rate-limited.
"""

import pytest
from fastapi.testclient import TestClient

from secure_ai_research.api.deps import get_service
from secure_ai_research.api.main import app
from secure_ai_research.config import get_settings
from secure_ai_research.ingestion import nvd
from secure_ai_research.ingestion.fetch_cve import research_from_source
from secure_ai_research.ingestion.nvd_source import CachingCveSource, NvdApiSource
from secure_ai_research.research_service import Outcome


@pytest.mark.integration
def test_live_nvd_fetch_to_cited_answer(tmp_path):
    source = CachingCveSource(NvdApiSource(), tmp_path / "cache")
    try:
        docs = nvd.load(source.fetch_raw("CVE-2021-44228"))
    except ValueError as exc:
        pytest.skip(f"NVD unreachable/rate-limited: {exc}")
    assert docs and docs[0].document.document_id == "CVE-2021-44228"
    res = research_from_source(
        "CVE-2021-44228",
        role="research_analyst",
        source=source,
        audit_path=tmp_path / "audit.jsonl",
    )
    assert res.outcome is Outcome.OK
    assert any(c.document_id == "CVE-2021-44228" for c in res.citations)


@pytest.mark.integration
def test_live_endpoint_fetches_real_cve(tmp_path, monkeypatch):
    # The wired, opt-in endpoint answers a real CVE absent from the packaged fixture by
    # fetching it live from NVD. Audit + cache go to tmp so the real paths are untouched.
    monkeypatch.setenv("SAIR_ALLOW_LIVE_FETCH", "true")
    monkeypatch.setenv("SAIR_NVD_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    get_settings.cache_clear()
    get_service.cache_clear()
    try:
        resp = TestClient(app).get(
            "/research/cve/CVE-2021-44228", headers={"X-Role": "research_analyst"}
        )
        # A network failure surfaces through the wired service as CveUnavailable →
        # FETCH_ERROR → 503 (not a bubbling exception), so skip on 503 rather than fail
        # when NVD is unreachable or rate-limited.
        if resp.status_code == 503:
            pytest.skip("NVD unreachable/rate-limited (503)")
        assert resp.status_code == 200
        assert any(c["document_id"] == "CVE-2021-44228" for c in resp.json()["citations"])
    finally:
        get_service.cache_clear()
        get_settings.cache_clear()
