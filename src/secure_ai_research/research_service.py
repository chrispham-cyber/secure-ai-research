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

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from secure_ai_research.audit.record import ResearchRecord, emit
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import ResearchDocument
from secure_ai_research.reporting.report import build_report
from secure_ai_research.retrieval.chunking import chunk
from secure_ai_research.retrieval.ports import ChunkRecord, Embedder, VectorStore


class Outcome(StrEnum):
    OK = "ok"
    DENIED = "denied"
    NOT_FOUND = "not_found"


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
    ) -> None:
        self._embedder = embedder
        self._store = store
        self._authorize = authorize
        self._audit_path = audit_path
        self._limit = limit
        self._docs: dict[str, ResearchDocument] = {}

    def index(self, docs: list[IngestedDocument]) -> None:
        for item in docs:
            doc = item.document
            if doc.document_id in self._docs:
                # Fail loud rather than silently append stale duplicate chunks that
                # would stay queryable alongside the new ones.
                raise ValueError(f"document already indexed: {doc.document_id}")
            self._docs[doc.document_id] = doc
            chunks = chunk(item.text)
            vectors = self._embedder.embed(chunks)
            self._store.upsert(
                [
                    ChunkRecord(f"{doc.document_id}#{i}", doc.document_id, chunks[i], vectors[i])
                    for i in range(len(chunks))
                ]
            )

    def research_cve(self, cve_id: str, *, role: str) -> ResearchResult:
        rid = uuid.uuid4().hex
        analyst_id = role.strip() or "anonymous"
        objective = f"Correlate {cve_id} against public sources"
        now = datetime.now(UTC)

        # Authorize before retrieval: the scope is what the role may see, intersected
        # with the requested CVE. A document outside this set is never queried.
        allowed = {did for did, doc in self._docs.items() if self._authorize(role, doc)}
        scope = allowed & {cve_id}

        # Role-level deny: the caller may retrieve nothing at all.
        if not allowed:
            self._emit_terminal(rid, analyst_id, objective, now, Outcome.DENIED)
            return ResearchResult(Outcome.DENIED, "", [], rid)

        # The CVE is not retrievable in the caller's scope — absent from the corpus,
        # or present but outside the caller's authorization. Both yield the same
        # response (no existence oracle) and the store is never queried empty-scoped.
        if not scope:
            self._emit_terminal(rid, analyst_id, objective, now, Outcome.NOT_FOUND)
            return ResearchResult(Outcome.NOT_FOUND, "", [], rid)

        hits = self._store.query(
            self._embedder.embed([cve_id])[0],
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

    def _emit_terminal(
        self,
        rid: str,
        analyst_id: str,
        objective: str,
        now: datetime,
        outcome: Outcome,
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
                conclusion=f"{outcome.value}: no corpus retrieved",
            ),
            self._audit_path,
        )
