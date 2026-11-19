"""Live NVD fetch — excluded from the default suite and CI (``-m "not integration"``).

Run explicitly with ``.venv/bin/python -m pytest -m integration``. Keyless; skips
(does not fail) when NVD is unreachable or rate-limited.
"""

import pytest

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
