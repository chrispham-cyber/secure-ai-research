from datetime import date
from importlib.resources import files

import pytest

from secure_ai_research.audit.record import read_records
from secure_ai_research.ingestion import kev, nvd
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import Classification, DocumentType, ResearchDocument
from secure_ai_research.ingestion.source import CveNotFound, CveUnavailable
from secure_ai_research.research_service import Outcome, ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.ports import ChunkHit
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


def test_present_but_unauthorized_cve_is_indistinguishable_from_absent(tmp_path):
    # A role authorized for one document but not another must not learn the other
    # exists: requesting the present-but-unauthorized doc returns NOT_FOUND (never
    # OK with empty citations), and the store is never queried with an empty scope.
    audit = tmp_path / "audit.jsonl"

    def only_0001(role: str, doc) -> bool:
        return doc.document_id == "CVE-2099-0001"

    spy = _SpyStore()
    svc = ResearchService(HashingEmbedder(), spy, only_0001, audit)
    svc.index(_docs())  # indexes both CVE-2099-0001 and CVE-2099-0002

    res = svc.research_cve("CVE-2099-0002", role="research_analyst")
    assert res.outcome is Outcome.NOT_FOUND
    assert res.citations == []
    assert spy.query_calls == 0
    assert read_records(audit)[0].retrieved_doc_ids == []


def test_reindexing_duplicate_document_id_is_rejected(tmp_path):
    # Re-indexing an already-indexed id must fail loud, not silently append stale
    # duplicate chunks that stay queryable.
    audit = tmp_path / "audit.jsonl"
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit)
    svc.index(_docs())
    with pytest.raises(ValueError, match="already indexed"):
        svc.index(_docs())


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


# --- fetch-on-miss (Phase-2 fetch-on-miss slice) ---


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


def _svc_with_fetch(audit, fetch) -> ResearchService:
    # Mirror the live app: a non-empty fixture corpus so an authorized role clears the
    # role-level DENIED gate, then the fetch-on-miss branch handles an un-indexed CVE.
    svc = ResearchService(
        HashingEmbedder(), InMemoryVectorStore(), authorize, audit, fetch_missing=fetch
    )
    svc.index(_docs())
    return svc


def test_fetch_on_miss_returns_cited_answer(tmp_path):
    audit = tmp_path / "audit.jsonl"
    fetch = _FakeFetch(docs=[_one_doc("CVE-2099-7777")])
    res = _svc_with_fetch(audit, fetch).research_cve("CVE-2099-7777", role="research_analyst")

    assert res.outcome is Outcome.OK
    assert fetch.calls == 1
    assert [c for c in res.citations if c.document_id == "CVE-2099-7777"]
    assert len(read_records(audit)) == 1  # exactly one audit record for the fetched OK


def test_fetch_absent_returns_not_found(tmp_path):
    audit = tmp_path / "audit.jsonl"
    fetch = _FakeFetch(exc=CveNotFound("absent"))
    res = _svc_with_fetch(audit, fetch).research_cve("CVE-2099-7777", role="research_analyst")

    assert res.outcome is Outcome.NOT_FOUND
    assert res.citations == []
    assert len(read_records(audit)) == 1


def test_fetch_unavailable_returns_fetch_error(tmp_path):
    audit = tmp_path / "audit.jsonl"
    fetch = _FakeFetch(exc=CveUnavailable("nvd down"))
    res = _svc_with_fetch(audit, fetch).research_cve("CVE-2099-7777", role="research_analyst")

    assert res.outcome is Outcome.FETCH_ERROR
    assert len(read_records(audit)) == 1


def test_denied_role_never_fetches(tmp_path):
    audit = tmp_path / "audit.jsonl"
    fetch = _FakeFetch(docs=[_one_doc("CVE-2099-7777")])
    res = _svc_with_fetch(audit, fetch).research_cve("CVE-2099-7777", role="")

    assert res.outcome is Outcome.DENIED
    assert fetch.calls == 0  # unauthorized callers never trigger an outbound fetch


def test_miss_without_fetch_missing_is_not_found(tmp_path):
    audit = tmp_path / "audit.jsonl"
    # fetch_missing defaults to None → today's offline behavior for an un-indexed CVE.
    res = _svc(audit).research_cve("CVE-2099-7777", role="research_analyst")

    assert res.outcome is Outcome.NOT_FOUND
    assert len(read_records(audit)) == 1


def test_fetch_records_name_the_fetch(tmp_path):
    absent_audit = tmp_path / "absent.jsonl"
    _svc_with_fetch(absent_audit, _FakeFetch(exc=CveNotFound("x"))).research_cve(
        "CVE-2099-7777", role="research_analyst"
    )
    error_audit = tmp_path / "error.jsonl"
    _svc_with_fetch(error_audit, _FakeFetch(exc=CveUnavailable("x"))).research_cve(
        "CVE-2099-7777", role="research_analyst"
    )
    never_audit = tmp_path / "never.jsonl"
    _svc(never_audit).research_cve("CVE-2099-7777", role="research_analyst")

    assert "live fetch" in read_records(absent_audit)[0].conclusion
    assert "unavailable" in read_records(error_audit)[0].conclusion
    assert "no corpus retrieved" in read_records(never_audit)[0].conclusion


def test_index_if_absent_is_idempotent(tmp_path):
    audit = tmp_path / "audit.jsonl"
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit)
    item = _one_doc("CVE-2099-7777")
    svc._index_if_absent([item])
    svc._index_if_absent([item])  # second call is a no-op; must not raise or duplicate

    res = svc.research_cve("CVE-2099-7777", role="research_analyst")
    assert res.outcome is Outcome.OK


def test_fetch_oserror_becomes_fetch_error(tmp_path):
    # fetch_missing is arbitrary injected code: a filesystem/IO failure (e.g. an unreadable
    # or unwritable cache file) must become FETCH_ERROR with exactly one audit record —
    # never an unhandled 500 and never a live fetch that leaves no audit trail.
    audit = tmp_path / "audit.jsonl"
    fetch = _FakeFetch(exc=OSError("disk full"))
    res = _svc_with_fetch(audit, fetch).research_cve("CVE-2099-7777", role="research_analyst")

    assert res.outcome is Outcome.FETCH_ERROR
    assert len(read_records(audit)) == 1


def test_fetch_unexpected_exception_becomes_fetch_error(tmp_path):
    # Any non-typed failure escaping the callable (e.g. http.client.HTTPException, which is
    # not an OSError, or a plain bug) is contained the same way: the service guarantees the
    # invariant rather than trusting the callable to raise only the two typed errors.
    audit = tmp_path / "audit.jsonl"
    fetch = _FakeFetch(exc=RuntimeError("boom"))
    res = _svc_with_fetch(audit, fetch).research_cve("CVE-2099-7777", role="research_analyst")

    assert res.outcome is Outcome.FETCH_ERROR
    assert len(read_records(audit)) == 1


# --- ATT&CK technique path (Phase-2 ATT&CK endpoint slice) ---


def _technique_doc(tid="T1059") -> IngestedDocument:
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


def _svc_tech(audit, *, fetch=None) -> ResearchService:
    svc = ResearchService(
        HashingEmbedder(), InMemoryVectorStore(), authorize, audit, fetch_missing=fetch
    )
    svc.index([_technique_doc("T1059")])
    return svc


def test_research_attack_returns_cited_answer(tmp_path):
    audit = tmp_path / "a.jsonl"
    res = _svc_tech(audit).research_attack("T1059", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert "T1059" in res.answer
    assert [c for c in res.citations if c.document_id == "T1059"]
    recs = read_records(audit)
    assert len(recs) == 1
    assert recs[0].data_source_ids == ["MITRE ATT&CK"]


def test_research_attack_denied(tmp_path):
    res = _svc_tech(tmp_path / "a.jsonl").research_attack("T1059", role="")
    assert res.outcome is Outcome.DENIED


def test_research_attack_absent_is_not_found(tmp_path):
    audit = tmp_path / "a.jsonl"
    res = _svc_tech(audit).research_attack("T9999", role="research_analyst")
    assert res.outcome is Outcome.NOT_FOUND
    assert len(read_records(audit)) == 1


def test_research_attack_never_fetches(tmp_path):
    # A CVE fetcher is wired, but the attack path must never call it, even on a miss.
    spy = _FakeFetch(docs=[_one_doc("CVE-2099-7777")])
    res = _svc_tech(tmp_path / "a.jsonl", fetch=spy).research_attack(
        "T9999", role="research_analyst"
    )
    assert res.outcome is Outcome.NOT_FOUND
    assert spy.calls == 0


# --- corpus search (Phase-2 search endpoint slice) ---


def _mk(doc_id, source, source_url, text):
    doc = ResearchDocument(
        document_id=doc_id,
        source=source,
        document_type=DocumentType.VULNERABILITY,
        classification=Classification.PUBLIC,
        created_at=date(2099, 1, 1),
        source_url=source_url,  # type: ignore[arg-type]
        integrity_hash="sha256:" + "0" * 64,
    )
    return IngestedDocument(doc, text)


def _search_svc(audit, authorize_fn=authorize) -> ResearchService:
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize_fn, audit)
    svc.index(
        [
            _mk(
                "CVE-2099-0001",
                "NVD",
                "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
                "widget widget widget",
            ),
            _mk(
                "T1059",
                "MITRE ATT&CK",
                "https://attack.mitre.org/techniques/T1059/",
                "widget alpha",
            ),
        ]
    )
    return svc


class _ZeroScoreStore(InMemoryVectorStore):
    def query(self, embedding, *, allowed_document_ids, limit):
        return [ChunkHit(did, "irrelevant", 0.0) for did in sorted(allowed_document_ids)][:limit]


def test_search_ranks_across_sources(tmp_path):
    audit = tmp_path / "a.jsonl"
    res = _search_svc(audit).search("widget", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert [c.document_id for c in res.citations] == ["CVE-2099-0001", "T1059"]  # 3×widget first
    assert res.citations[0].source_url == "https://nvd.nist.gov/vuln/detail/CVE-2099-0001"
    recs = read_records(audit)
    assert len(recs) == 1
    assert recs[0].retrieved_doc_ids == ["CVE-2099-0001", "T1059"]
    assert recs[0].data_source_ids == ["MITRE ATT&CK", "NVD"]  # sorted


def test_search_excludes_unauthorized_documents(tmp_path):
    def only_cve(role, doc):
        return doc.document_id.startswith("CVE-")

    res = _search_svc(tmp_path / "a.jsonl", only_cve).search("widget", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert [c.document_id for c in res.citations] == ["CVE-2099-0001"]  # T1059 authorized out


def test_search_denied_role_never_queries_store(tmp_path):
    audit = tmp_path / "a.jsonl"
    spy = _SpyStore()
    svc = ResearchService(HashingEmbedder(), spy, authorize, audit)
    svc.index(
        [_mk("CVE-2099-0001", "NVD", "https://nvd.nist.gov/vuln/detail/CVE-2099-0001", "widget")]
    )
    res = svc.search("widget", role="")
    assert res.outcome is Outcome.DENIED
    assert res.citations == []
    assert spy.query_calls == 0
    assert read_records(audit)[0].retrieved_doc_ids == []


def test_search_no_match_is_ok_empty(tmp_path):
    audit = tmp_path / "a.jsonl"
    svc = ResearchService(HashingEmbedder(), _ZeroScoreStore(), authorize, audit)
    svc.index(
        [_mk("CVE-2099-0001", "NVD", "https://nvd.nist.gov/vuln/detail/CVE-2099-0001", "widget")]
    )
    res = svc.search("anything", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert res.citations == []
    recs = read_records(audit)
    assert len(recs) == 1
    assert recs[0].retrieved_doc_ids == []


def test_search_dedups_to_best_passage_per_document(tmp_path):
    audit = tmp_path / "a.jsonl"
    text = " ".join(f"widget word{i}" for i in range(300))  # widget in every chunk, >800 chars
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit)
    svc.index([_mk("CVE-2099-0001", "NVD", "https://nvd.nist.gov/vuln/detail/CVE-2099-0001", text)])
    res = svc.search("widget", role="research_analyst", limit=5)
    assert res.outcome is Outcome.OK
    assert [c.document_id for c in res.citations] == ["CVE-2099-0001"]  # one entry despite chunks


# --- KEV coexistence (Phase-2 KEV loader slice) ---


def test_kev_does_not_shadow_cve_route(tmp_path):
    # A KEV doc for the same CVE as an NVD fixture doc coexists (namespaced id) and the
    # CVE id-route still returns the NVD document, never the KEV one.
    import json

    audit = tmp_path / "a.jsonl"
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit)
    svc.index(_docs())  # NVD CVE-2099-0001 / CVE-2099-0002
    kev_raw = json.dumps(
        {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2099-0001",
                    "dateAdded": "2099-01-01",
                    "vulnerabilityName": "dup",
                    "shortDescription": "s",
                    "requiredAction": "a",
                }
            ]
        }
    ).encode()
    svc.index(kev.load(kev_raw))  # must NOT raise (KEV id is KEV-CVE-2099-0001)
    res = svc.research_cve("CVE-2099-0001", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert all(c.document_id == "CVE-2099-0001" for c in res.citations)  # never KEV-…
