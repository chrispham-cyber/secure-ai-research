from importlib.resources import files

from secure_ai_research.ingestion.fetch_cve import research_from_source
from secure_ai_research.research_service import Outcome

VALID = files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()


class FixtureCveSource:  # test double; returns packaged bytes as-is
    def __init__(self, raw: bytes = VALID):
        self._raw = raw

    def fetch_raw(self, cve_id: str) -> bytes:
        return self._raw


def test_offline_end_to_end_cited_answer(tmp_path):
    res = research_from_source(
        "CVE-2099-0001",
        role="research_analyst",
        source=FixtureCveSource(),
        audit_path=tmp_path / "audit.jsonl",
    )
    assert res.outcome is Outcome.OK
    assert any(c.document_id == "CVE-2099-0001" for c in res.citations)


def test_requested_id_absent_from_feed_is_not_found(tmp_path):
    res = research_from_source(
        "CVE-2099-9999",  # not in the 2-CVE fixture
        role="research_analyst",
        source=FixtureCveSource(),
        audit_path=tmp_path / "audit.jsonl",
    )
    assert res.outcome is Outcome.NOT_FOUND
    assert res.citations == []
