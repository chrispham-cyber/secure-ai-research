"""Provenance is persisted at the index boundary, and a store fault there fails closed
(Phase 5, Slice 3, Task 4).

Three guarantees:
1. every indexed document's canonical bytes are put to the object store under its integrity_hash;
2. an object-store fault during a fetch-on-miss re-index becomes FETCH_ERROR + exactly one audit
   record (never an unhandled 500), the sibling of the Slice-2 vector-upsert invariant;
3. the default path (in-memory object store) is a normal OK and never imports the minio SDK.
"""

from __future__ import annotations

import hashlib
import sys
from importlib.resources import files
from pathlib import Path

from secure_ai_research.ingestion import nvd
from secure_ai_research.research_service import Outcome, ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore
from secure_ai_research.storage.ports import ObjectStoreError


def _nvd_sample_bytes() -> bytes:
    return files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()


def _audit_lines(p: Path) -> list[str]:
    return [line for line in p.read_text().splitlines() if line.strip()]


class _SpyStore:
    """Records every put; get is unused by the write path."""

    def __init__(self) -> None:
        self.puts: list[tuple[str, bytes]] = []

    def put(self, key: str, data: bytes) -> None:
        self.puts.append((key, data))

    def get(self, key: str) -> bytes:
        raise ObjectStoreError(key)


def test_index_persists_canonical_keyed_by_hash(tmp_path):
    spy = _SpyStore()
    docs = nvd.load(_nvd_sample_bytes())
    svc = ResearchService(
        HashingEmbedder(),
        InMemoryVectorStore(),
        authorize,
        tmp_path / "a.jsonl",
        object_store=spy,
    )
    svc.index(docs)
    # every indexed doc's canonical bytes are stored under its own integrity_hash
    assert {k for k, _ in spy.puts} == {d.document.integrity_hash for d in docs}
    for k, data in spy.puts:
        assert hashlib.sha256(data).hexdigest() == k.removeprefix("sha256:")


class _PutRaisesWhenArmed:
    """Object store whose put raises once armed — fails the request-time re-index of a freshly
    fetched CVE without breaking the initial corpus index."""

    def __init__(self) -> None:
        self.armed = False

    def put(self, key: str, data: bytes) -> None:
        if self.armed:
            raise ObjectStoreError("minio down during put")

    def get(self, key: str) -> bytes:
        raise ObjectStoreError(key)


def test_object_store_fault_on_live_fetch_is_fetch_error_one_record(tmp_path):
    # provenance put runs inside _index_one, BEFORE the vector upsert, on the fetch-on-miss path;
    # an outage there must STILL fail closed — FETCH_ERROR with exactly one audit record, type
    # only — never an unhandled 500. Only senior_analyst may live-fetch.
    audit = tmp_path / "audit.jsonl"
    store = _PutRaisesWhenArmed()
    docs = nvd.load(_nvd_sample_bytes())
    svc = ResearchService(
        HashingEmbedder(),
        InMemoryVectorStore(),
        authorize,
        audit,
        fetch_missing=lambda _cid: nvd.load(_nvd_sample_bytes()),
        object_store=store,
    )
    svc.index([docs[0]])  # index CVE-2099-0001 only → senior is authorized (not DENIED)
    store.armed = True  # the next put (re-index of the fetched doc) will raise
    res = svc.research_cve("CVE-2099-0002", role="senior_analyst")  # absent → fetch → re-index
    assert res.outcome is Outcome.FETCH_ERROR
    assert res.answer == ""
    assert res.citations == []
    assert len(_audit_lines(audit)) == 1  # exactly one record — not zero (no silent 500)
    assert "minio down during put" not in audit.read_text()  # only the exception type recorded


def test_default_path_result_unchanged_and_no_minio_import(tmp_path):
    # Default object store (None → InMemoryObjectStore): the happy path is a normal OK and the
    # minio SDK is never imported by the default/hermetic path.
    docs = nvd.load(_nvd_sample_bytes())
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, tmp_path / "a.jsonl")
    svc.index(docs)
    res = svc.research_cve(docs[0].document.document_id, role="research_analyst")
    assert res.outcome is Outcome.OK
    assert "minio" not in sys.modules
