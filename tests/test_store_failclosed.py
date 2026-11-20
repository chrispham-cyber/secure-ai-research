"""Fail-closed wiring for vector-store faults (Phase 5, Slice 2, Task 1).

A real ``VectorStore`` (pgvector) can fail at request time — a dropped connection, a query
error. These tests prove the service treats any such fault exactly like a generator/fetcher
fault: ``Outcome.FETCH_ERROR`` with **exactly one** audit record (recording only the exception
type, never a payload), on every request path that queries the store. Proven hermetically with
raising fakes — no Postgres — the direct analogue of Slice 1a's generator-fail-closed tests.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import pytest

from secure_ai_research.ingestion import nvd
from secure_ai_research.research_service import Outcome, ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.ports import VectorStoreError


def _nvd_sample_bytes() -> bytes:
    return files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()


class _RaisingTypedStore:
    """VectorStore whose query raises the typed VectorStoreError; upsert is a no-op so the
    service's _docs still populates and the request reaches store.query with a non-empty scope."""

    def upsert(self, entries) -> None:  # noqa: ANN001 - test fake
        return None

    def query(self, embedding, *, allowed_document_ids, limit):  # noqa: ANN001 - test fake
        raise VectorStoreError("pg down")


class _RaisingBroadStore:
    """VectorStore whose query raises a NON-typed error — exercises the defense-in-depth arm."""

    def upsert(self, entries) -> None:  # noqa: ANN001 - test fake
        return None

    def query(self, embedding, *, allowed_document_ids, limit):  # noqa: ANN001 - test fake
        raise RuntimeError("socket closed")


def _service(store, audit_path: Path) -> ResearchService:
    svc = ResearchService(HashingEmbedder(), store, authorize, audit_path)
    svc.index(nvd.load(_nvd_sample_bytes()))
    return svc


def _audit_lines(p: Path) -> list[str]:
    return [line for line in p.read_text().splitlines() if line.strip()]


@pytest.mark.parametrize("store_cls", [_RaisingTypedStore, _RaisingBroadStore])
@pytest.mark.parametrize(
    "call",
    [
        lambda s: s.search("sql injection", role="research_analyst"),
        lambda s: s.ask("sql injection", role="research_analyst"),
        lambda s: s.research_cve("CVE-2099-0001", role="research_analyst"),
    ],
    ids=["search", "ask", "cve"],
)
def test_store_failure_is_fetch_error_with_one_audit_record(tmp_path, store_cls, call):
    audit = tmp_path / "audit.jsonl"
    res = call(_service(store_cls(), audit))
    assert res.outcome is Outcome.FETCH_ERROR
    assert res.answer == ""
    assert res.citations == []
    assert len(_audit_lines(audit)) == 1  # exactly one record on the failure path
    assert "pg down" not in audit.read_text()  # payload not leaked (only the exception type)
    assert "socket closed" not in audit.read_text()


def test_denied_role_never_reaches_store_no_fetch_error(tmp_path):
    # A role authorized for nothing is DENIED and never queries the store, so a raising
    # store can never turn a DENIED into a FETCH_ERROR.
    res = _service(_RaisingTypedStore(), tmp_path / "a.jsonl").search("x", role="")
    assert res.outcome is Outcome.DENIED


class _UpsertRaisesWhenArmed:
    """VectorStore whose upsert raises once armed — fails the request-time re-index of a
    freshly fetched CVE (fetch-on-miss) without breaking the initial corpus index."""

    def __init__(self) -> None:
        self.armed = False

    def upsert(self, entries) -> None:  # noqa: ANN001 - test fake
        if self.armed:
            raise VectorStoreError("pg down during upsert")

    def query(self, embedding, *, allowed_document_ids, limit):  # noqa: ANN001 - test fake
        return []


def test_cve_live_fetch_reindex_upsert_failure_is_fetch_error_one_record(tmp_path):
    # Fetch-on-miss re-indexes the fetched CVE via self._store.upsert, which is OUTSIDE the
    # store.query try/except. A store outage there must STILL fail closed — FETCH_ERROR with
    # exactly one audit record — never an unhandled 500 that leaves no audit trail (the precise
    # invariant Review Focus #1 names). Only senior_analyst may live-fetch.
    audit = tmp_path / "audit.jsonl"
    store = _UpsertRaisesWhenArmed()
    docs = nvd.load(_nvd_sample_bytes())
    svc = ResearchService(
        HashingEmbedder(),
        store,
        authorize,
        audit,
        fetch_missing=lambda _cid: nvd.load(_nvd_sample_bytes()),
    )
    svc.index([docs[0]])  # index CVE-2099-0001 only → senior is authorized (not DENIED)
    store.armed = True  # the next upsert (re-index of the fetched doc) will raise
    res = svc.research_cve("CVE-2099-0002", role="senior_analyst")  # absent → fetch → re-index
    assert res.outcome is Outcome.FETCH_ERROR
    assert res.answer == ""
    assert res.citations == []
    assert len(_audit_lines(audit)) == 1  # exactly one record — not zero (no silent 500)
    assert "pg down during upsert" not in audit.read_text()  # only the exception type recorded
