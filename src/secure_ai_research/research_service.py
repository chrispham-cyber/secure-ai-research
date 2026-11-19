"""Research orchestration service (ROADMAP Phase 2).

The spine of the NVD retrieval slice: index ingested documents into a vector
store, then answer a CVE query end to end — authorize-before-retrieve,
deterministic cited assembly (no LLM), and exactly one append-only audit record
per request.

Authorization runs **before** the store is queried: the caller's authorized scope
is passed into the query as ``allowed_document_ids``, so a document the role may
not see is never retrieved and cannot leak into the answer. A denied or not-found
request still emits an audit record, but one carrying no corpus metadata.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from secure_ai_research.audit.record import ResearchRecord, emit
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import ResearchDocument
from secure_ai_research.ingestion.source import CveNotFound, CveUnavailable
from secure_ai_research.reporting.report import build_report
from secure_ai_research.retrieval.chunking import chunk
from secure_ai_research.retrieval.ports import ChunkRecord, Embedder, VectorStore


class Outcome(StrEnum):
    OK = "ok"
    DENIED = "denied"
    NOT_FOUND = "not_found"
    FETCH_ERROR = "fetch_error"


@dataclass(frozen=True)
class Citation:
    document_id: str
    source_url: str
    passage: str


@dataclass(frozen=True)
class ResearchResult:
    outcome: Outcome
    answer: str
    citations: list[Citation]
    research_id: str


class ResearchService:
    """Indexes documents and answers CVE queries with cited, audited retrieval."""

    def __init__(
        self,
        embedder: Embedder,
        store: VectorStore,
        authorize: Callable[[str, ResearchDocument], bool],
        audit_path: Path,
        limit: int = 5,
        *,
        fetch_missing: Callable[[str], list[IngestedDocument]] | None = None,
    ) -> None:
        self._embedder = embedder
        self._store = store
        self._authorize = authorize
        self._audit_path = audit_path
        self._limit = limit
        self._fetch_missing = fetch_missing
        self._docs: dict[str, ResearchDocument] = {}
        self._lock = threading.Lock()

    def index(self, docs: list[IngestedDocument]) -> None:
        with self._lock:
            for item in docs:
                if item.document.document_id in self._docs:
                    # Fail loud rather than silently append stale duplicate chunks that
                    # would stay queryable alongside the new ones.
                    raise ValueError(f"document already indexed: {item.document.document_id}")
                self._index_one(item)

    def _index_if_absent(self, docs: list[IngestedDocument]) -> None:
        # Fetch-on-miss path: a concurrent double-fetch of the same CVE must index it
        # exactly once, not raise. Skip any doc already present instead of failing loud.
        with self._lock:
            for item in docs:
                if item.document.document_id not in self._docs:
                    self._index_one(item)

    def _index_one(self, item: IngestedDocument) -> None:
        # Caller holds self._lock. Publish to self._docs LAST — after the chunks are
        # upserted — so a concurrent reader never sees a doc id whose chunks are not yet
        # queryable (which would be an OK with an empty answer and a wrong audit record).
        doc = item.document
        chunks = chunk(item.text)
        vectors = self._embedder.embed(chunks)
        self._store.upsert(
            [
                ChunkRecord(f"{doc.document_id}#{i}", doc.document_id, chunks[i], vectors[i])
                for i in range(len(chunks))
            ]
        )
        self._docs[doc.document_id] = doc

    def _snapshot(self) -> list[tuple[str, ResearchDocument]]:
        # Atomic copy of the id->doc pairs so the unlocked allowed/scope computation never
        # iterates self._docs while _index_one mutates it ("dict changed size").
        with self._lock:
            return list(self._docs.items())

    def _research(
        self,
        doc_id: str,
        *,
        role: str,
        objective: str,
        fetch_missing: Callable[[str], list[IngestedDocument]] | None = None,
    ) -> ResearchResult:
        rid = uuid.uuid4().hex
        analyst_id = role.strip() or "anonymous"
        now = datetime.now(UTC)

        # Authorize before retrieval: the scope is what the role may see, intersected
        # with the requested document. A document outside this set is never queried.
        allowed = {did for did, doc in self._snapshot() if self._authorize(role, doc)}
        scope = allowed & {doc_id}

        # Role-level deny: the caller may retrieve nothing at all.
        if not allowed:
            self._emit_terminal(rid, analyst_id, objective, now, "denied: no corpus retrieved")
            return ResearchResult(Outcome.DENIED, "", [], rid)

        # The document is not retrievable in the caller's scope — absent from the corpus,
        # or present but outside the caller's authorization. Both yield the same
        # response (no existence oracle) and the store is never queried empty-scoped.
        if not scope:
            # Fetch-on-miss (opt-in; only the CVE path passes a fetcher). We are already
            # past the role-level DENIED gate, so only an authorized caller ever reaches a
            # fetch (authz-first). The ``doc_id not in self._docs`` guard means a present-
            # but-unauthorized document is never fetched — it stays indistinguishable from
            # absent. A path that passes no fetcher (e.g. ATT&CK) simply skips this block.
            if fetch_missing is not None and doc_id not in self._docs:
                try:
                    fetched = fetch_missing(doc_id)
                except CveNotFound:
                    self._emit_terminal(
                        rid, analyst_id, objective, now, "not_found: live fetch returned no record"
                    )
                    return ResearchResult(Outcome.NOT_FOUND, "", [], rid)
                except CveUnavailable:
                    self._emit_terminal(
                        rid, analyst_id, objective, now, "fetch_error: NVD unavailable"
                    )
                    return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)
                except Exception as exc:
                    # Defense in depth: fetch_missing is arbitrary injected code. Any
                    # failure other than the two typed ones (e.g. an OSError from the cache
                    # file, or an http.client.HTTPException that is not an OSError) must
                    # still become FETCH_ERROR with exactly one audit record — never an
                    # unhandled 500, never a live fetch that leaves no audit trail. Only the
                    # exception *type* is recorded, so a message payload cannot leak.
                    self._emit_terminal(
                        rid,
                        analyst_id,
                        objective,
                        now,
                        f"fetch_error: live fetch failed ({type(exc).__name__})",
                    )
                    return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)
                self._index_if_absent(fetched)
                allowed = {did for did, doc in self._snapshot() if self._authorize(role, doc)}
                scope = allowed & {doc_id}

            if not scope:
                self._emit_terminal(
                    rid, analyst_id, objective, now, "not_found: no corpus retrieved"
                )
                return ResearchResult(Outcome.NOT_FOUND, "", [], rid)

        hits = self._store.query(
            self._embedder.embed([doc_id])[0],
            allowed_document_ids=scope,
            limit=self._limit,
        )

        ordered_ids: list[str] = []
        first_text: dict[str, str] = {}
        for hit in hits:
            if hit.document_id not in first_text:
                ordered_ids.append(hit.document_id)
                first_text[hit.document_id] = hit.text

        citations = [
            Citation(did, str(self._docs[did].source_url), first_text[did]) for did in ordered_ids
        ]
        model_output = "\n".join(f"{hit.text} [{hit.document_id}]" for hit in hits)

        record = ResearchRecord(
            research_id=rid,
            analyst_id=analyst_id,
            timestamp=now,
            objective=objective,
            data_source_ids=sorted({self._docs[did].source for did in ordered_ids}),
            document_hashes=[self._docs[did].integrity_hash for did in ordered_ids],
            model_id="retrieval-only",
            model_version="",
            prompt_template_version="",
            retrieved_doc_ids=ordered_ids,
            model_output=model_output,
            conclusion="retrieval-only: assembled from cited passages",
        )
        answer = build_report(record)
        emit(record, self._audit_path)
        return ResearchResult(Outcome.OK, answer, citations, rid)

    def research_cve(self, cve_id: str, *, role: str) -> ResearchResult:
        """Correlate a CVE against public sources (NVD), fetching on a miss if enabled."""
        return self._research(
            cve_id,
            role=role,
            objective=f"Correlate {cve_id} against public sources",
            fetch_missing=self._fetch_missing,
        )

    def research_attack(self, technique_id: str, *, role: str) -> ResearchResult:
        """Explain a MITRE ATT&CK technique from cited public sources.

        Fixture-backed only: no fetcher is passed, so an un-indexed technique resolves to
        NOT_FOUND and the CVE fetch path is never reached with a technique id.
        """
        return self._research(
            technique_id,
            role=role,
            objective=f"Explain ATT&CK technique {technique_id} with cited public sources",
        )

    def _emit_terminal(
        self,
        rid: str,
        analyst_id: str,
        objective: str,
        now: datetime,
        conclusion: str,
    ) -> None:
        emit(
            ResearchRecord(
                research_id=rid,
                analyst_id=analyst_id,
                timestamp=now,
                objective=objective,
                data_source_ids=[],
                document_hashes=[],
                model_id="retrieval-only",
                model_version="",
                prompt_template_version="",
                retrieved_doc_ids=[],
                model_output="",
                conclusion=conclusion,
            ),
            self._audit_path,
        )
