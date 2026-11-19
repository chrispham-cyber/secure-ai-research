from datetime import date
from importlib.resources import files

from secure_ai_research.audit.record import read_records
from secure_ai_research.ingestion import nvd
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import Classification, DocumentType, ResearchDocument
from secure_ai_research.research_service import Outcome, ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore


def _docs() -> list[IngestedDocument]:
    raw = files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()
    return nvd.load(raw)


def _svc(audit_path, store=None) -> ResearchService:
    svc = ResearchService(HashingEmbedder(), store or InMemoryVectorStore(), authorize, audit_path)
    svc.index(_docs())
    return svc


def test_permitted_role_gets_cited_answer(tmp_path):
    audit = tmp_path / "audit.jsonl"
    res = _svc(audit).research_cve("CVE-2099-0001", role="research_analyst")

    assert res.outcome is Outcome.OK
    assert "CVE-2099-0001" in res.answer
    cites = [c for c in res.citations if c.document_id == "CVE-2099-0001"]
    assert cites and cites[0].source_url == "https://nvd.nist.gov/vuln/detail/CVE-2099-0001"

    records = read_records(audit)
    assert len(records) == 1
    r = records[0]
    assert r.analyst_id == "research_analyst"
    assert r.data_source_ids == ["NVD"]
    assert r.model_id == "retrieval-only"
    assert r.retrieved_doc_ids == ["CVE-2099-0001"]
    assert r.research_id == res.research_id


class _SpyStore(InMemoryVectorStore):
    def __init__(self) -> None:
        super().__init__()
        self.query_calls = 0

    def query(self, embedding, *, allowed_document_ids, limit):
        self.query_calls += 1
        return super().query(embedding, allowed_document_ids=allowed_document_ids, limit=limit)


def test_denied_role_never_queries_store(tmp_path):
    audit = tmp_path / "audit.jsonl"
    spy = _SpyStore()
    res = _svc(audit, store=spy).research_cve("CVE-2099-0001", role="")

    assert res.outcome is Outcome.DENIED
    assert res.citations == []
    assert spy.query_calls == 0

    r = read_records(audit)[0]
    assert r.retrieved_doc_ids == []
    assert r.document_hashes == []


def test_absent_cve_is_not_found(tmp_path):
    audit = tmp_path / "audit.jsonl"
    res = _svc(audit).research_cve("CVE-2099-9999", role="research_analyst")

    assert res.outcome is Outcome.NOT_FOUND
    r = read_records(audit)[0]
    assert r.retrieved_doc_ids == []
    assert r.document_hashes == []


def test_multiline_answer_round_trips_as_one_record(tmp_path):
    audit = tmp_path / "audit.jsonl"
    long_text = "CVE-2099-5555 " + " ".join(f"word{i}" for i in range(400))  # >800 chars
    doc = ResearchDocument(
        document_id="CVE-2099-5555",
        source="NVD",
        document_type=DocumentType.VULNERABILITY,
        classification=Classification.PUBLIC,
        created_at=date(2099, 1, 1),
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2099-5555",  # type: ignore[arg-type]
        integrity_hash="sha256:" + "0" * 64,
    )
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit)
    svc.index([IngestedDocument(doc, long_text)])

    res = svc.research_cve("CVE-2099-5555", role="research_analyst")
    assert res.outcome is Outcome.OK

    records = read_records(audit)
    assert len(records) == 1  # multi-line model_output stays one append-only record
    assert "\n" in records[0].model_output  # genuinely multi-line
