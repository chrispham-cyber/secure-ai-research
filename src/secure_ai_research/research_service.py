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

import logging
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from secure_ai_research.audit.record import ResearchRecord, emit
from secure_ai_research.audit.signing import DEV_AUDIT_KEY
from secure_ai_research.crypto.ports import Cipher
from secure_ai_research.generation.join import JoinGenerator
from secure_ai_research.generation.ports import Generator, GeneratorError
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import ResearchDocument
from secure_ai_research.ingestion.source import CveNotFound, CveUnavailable
from secure_ai_research.reporting.report import build_report
from secure_ai_research.retrieval.authz import may_live_fetch
from secure_ai_research.retrieval.chunking import chunk
from secure_ai_research.retrieval.ports import (
    ChunkHit,
    ChunkRecord,
    Embedder,
    VectorStore,
    VectorStoreError,
)
from secure_ai_research.storage.objectstore import InMemoryObjectStore
from secure_ai_research.storage.ports import ObjectStore, ObjectStoreError


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


@dataclass(frozen=True)
class _CorpusRetrieval:
    """Authorize-before-retrieve over the whole authorized corpus (shared by ``search`` and
    ``ask``). When ``allowed`` is empty the store is **not** queried and the other fields are
    empty; the caller emits its own terminal DENIED record. ``hits`` are relevance-floored
    (``score > 0``); ``ordered_ids``/``citations`` are the per-document dedup in hit order.
    """

    allowed: set[str]
    hits: list[ChunkHit]
    ordered_ids: list[str]
    citations: list[Citation]


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
        generator: Generator | None = None,
        object_store: ObjectStore | None = None,
        audit_key: str = DEV_AUDIT_KEY,
        audit_cipher: Cipher | None = None,
    ) -> None:
        self._embedder = embedder
        self._store = store
        self._authorize = authorize
        self._audit_path = audit_path
        self._limit = limit
        self._fetch_missing = fetch_missing
        # Signing key + optional at-rest cipher for the audit chain. Default dev key keeps the
        # offline suite self-verifying; a prod deployment injects a strong key via deps/startup.
        self._audit_key = audit_key
        self._audit_cipher = audit_cipher
        # Default = JoinGenerator: output byte-identical to the pre-seam id-route, so the
        # deterministic suite and the Phase-4 1.0 gate are unchanged with no real generator.
        self._generator = generator or JoinGenerator()
        # Default = InMemoryObjectStore: a dependency-free provenance sink, so the hermetic suite
        # never imports the minio SDK and the default path is byte-identical.
        self._object_store = object_store or InMemoryObjectStore()
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
        # Provenance-first: persist the raw canonical bytes under the content hash BEFORE the
        # vector upsert, so every indexed doc is backed by its stored source. A store fault here
        # raises ObjectStoreError and fails closed on the request path (see research_cve).
        self._object_store.put(doc.integrity_hash, item.canonical)
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
            # Fetch-on-miss (opt-in; only the CVE path passes a fetcher). We are already past
            # the role-level DENIED gate, so only an authorized caller reaches here (authz-
            # first). Fetch is further gated to ``may_live_fetch(role)``: only a role with no
            # present-but-hidden PUBLIC class (senior_analyst) may fetch, so for every other
            # role an absent id and a present-but-RESTRICTED id are identical — the same
            # NOT_FOUND response AND the same zero fetches (no timing/egress existence oracle).
            # The ``doc_id not in self._docs`` guard additionally keeps a present-but-
            # unauthorized document from being fetched. A path with no fetcher (e.g. ATT&CK)
            # skips this block.
            if fetch_missing is not None and may_live_fetch(role) and doc_id not in self._docs:
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
                try:
                    self._index_if_absent(fetched)
                except VectorStoreError as exc:
                    # The store faulted while re-indexing the freshly fetched CVE. This upsert
                    # is outside the store.query try/except below, so it must fail closed here
                    # too — one terminal record, FETCH_ERROR, exception type only — never an
                    # unhandled 500 that leaves an analyst's live-fetch action with no audit trail.
                    self._emit_terminal(
                        rid,
                        analyst_id,
                        objective,
                        now,
                        f"fetch_error: retrieval failed ({type(exc).__name__})",
                    )
                    return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)
                except ObjectStoreError as exc:
                    # Provenance put (inside _index_if_absent, before the vector upsert) faulted
                    # while persisting the freshly fetched CVE. Same contract as the vector store
                    # above — one terminal record, FETCH_ERROR, exception type only. The broad arm
                    # below would also catch it; this typed arm mirrors the VectorStoreError arm
                    # so object-store faults stay fail-closed if that broad net is ever narrowed.
                    self._emit_terminal(
                        rid,
                        analyst_id,
                        objective,
                        now,
                        f"fetch_error: retrieval failed ({type(exc).__name__})",
                    )
                    return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)
                except Exception as exc:
                    # Defense in depth: _index_if_absent also embeds; any non-typed failure must
                    # still become FETCH_ERROR with exactly one audit record, type only.
                    self._emit_terminal(
                        rid,
                        analyst_id,
                        objective,
                        now,
                        f"fetch_error: retrieval failed ({type(exc).__name__})",
                    )
                    return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)
                allowed = {did for did, doc in self._snapshot() if self._authorize(role, doc)}
                scope = allowed & {doc_id}

            if not scope:
                self._emit_terminal(
                    rid, analyst_id, objective, now, "not_found: no corpus retrieved"
                )
                return ResearchResult(Outcome.NOT_FOUND, "", [], rid)

        try:
            hits = self._store.query(
                self._embedder.embed([doc_id])[0],
                allowed_document_ids=scope,
                limit=self._limit,
            )
        except VectorStoreError as exc:
            # The vector store is unavailable / the query failed. Fail closed, mirroring the
            # generator path: one terminal audit record, FETCH_ERROR, only the exception type
            # recorded so a backend message cannot leak.
            self._emit_terminal(
                rid,
                analyst_id,
                objective,
                now,
                f"fetch_error: retrieval failed ({type(exc).__name__})",
            )
            return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)
        except Exception as exc:
            # Defense in depth: the store is injected via Protocol/factory, so any failure OTHER
            # than the typed VectorStoreError must still become FETCH_ERROR with exactly one audit
            # record, never an unhandled 500 that leaves no trail. Only the exception type is kept.
            self._emit_terminal(
                rid,
                analyst_id,
                objective,
                now,
                f"fetch_error: retrieval failed ({type(exc).__name__})",
            )
            return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)

        ordered_ids: list[str] = []
        first_text: dict[str, str] = {}
        for hit in hits:
            if hit.document_id not in first_text:
                ordered_ids.append(hit.document_id)
                first_text[hit.document_id] = hit.text

        citations = [
            Citation(did, str(self._docs[did].source_url), first_text[did]) for did in ordered_ids
        ]
        # Synthesis seam. The default JoinGenerator reproduces the pre-seam string exactly;
        # a configured real generator (Ollama) writes grounded prose over the same passages.
        passages = [f"{hit.text} [{hit.document_id}]" for hit in hits]
        gen = self._generator
        try:
            model_output = gen.generate(objective, passages)
        except GeneratorError as exc:
            # A real generator failed. Fail closed: one terminal audit record, FETCH_ERROR,
            # never a silent fallback to a different generator, never a fabricated answer.
            # Only the exception type is recorded, so a message payload cannot leak.
            self._emit_terminal(
                rid,
                analyst_id,
                objective,
                now,
                f"fetch_error: generation failed ({type(exc).__name__})",
            )
            return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)
        except Exception as exc:
            # Defense in depth, mirroring the injected-fetcher path: a generator is injected code
            # (Protocol/factory), so any failure OTHER than the typed GeneratorError — a urllib
            # ValueError from a misconfigured host scheme, a bug in a third-party generator — must
            # still become FETCH_ERROR with exactly one audit record, never an unhandled 500 that
            # leaves no audit trail. Only the exception type is recorded (no payload leak).
            self._emit_terminal(
                rid,
                analyst_id,
                objective,
                now,
                f"fetch_error: generation failed ({type(exc).__name__})",
            )
            return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)

        # Audit identity comes from the active generator (honest attribution). JoinGenerator
        # reports retrieval-only/""/"" ⇒ the default record is byte-identical to pre-change.
        model_id = getattr(gen, "model_id", "retrieval-only")
        model_version = getattr(gen, "model_version", "")
        prompt_template_version = getattr(gen, "prompt_template_version", "")

        record = ResearchRecord(
            research_id=rid,
            analyst_id=analyst_id,
            timestamp=now,
            objective=objective,
            data_source_ids=sorted({self._docs[did].source for did in ordered_ids}),
            document_hashes=[self._docs[did].integrity_hash for did in ordered_ids],
            model_id=model_id,
            model_version=model_version,
            prompt_template_version=prompt_template_version,
            retrieved_doc_ids=ordered_ids,
            model_output=model_output,
            conclusion=f"{model_id}: assembled from cited passages",
        )
        # Faithfulness floor: build_report drops any surviving line whose claim does not
        # overlap its cited passage text — catches a valid-id line with invented content.
        # Deterministic lines ARE the passage (+id), so they overlap fully and are unaffected.
        passages_by_id = {
            did: [hit.text for hit in hits if hit.document_id == did] for did in ordered_ids
        }
        answer = build_report(record, passages_by_id)
        emit(record, self._audit_path, key=self._audit_key, cipher=self._audit_cipher)
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

    def _retrieve_corpus(self, query: str, role: str, limit: int) -> _CorpusRetrieval:
        """Authorize-before-retrieve over the whole corpus the role may see, relevance-floored.

        Shared by ``search`` and ``ask``: the authorized scope is the whole set (not intersected
        with any id); the store is queried only when that set is non-empty, so a role that may see
        nothing never queries it; and zero-score chunks are dropped (cosine is 0 exactly when the
        query shares no token) so "nothing matched" is a real empty result, not non-matching junk.
        Authorization runs before retrieval here, in one place, for both callers.
        """
        allowed = {did for did, doc in self._snapshot() if self._authorize(role, doc)}
        if not allowed:
            return _CorpusRetrieval(allowed, [], [], [])
        hits = [
            h
            for h in self._store.query(
                self._embedder.embed([query])[0], allowed_document_ids=allowed, limit=limit
            )
            if h.score > 0
        ]
        ordered_ids: list[str] = []
        first_text: dict[str, str] = {}
        for hit in hits:
            if hit.document_id not in first_text:
                ordered_ids.append(hit.document_id)
                first_text[hit.document_id] = hit.text
        citations = [
            Citation(did, str(self._docs[did].source_url), first_text[did]) for did in ordered_ids
        ]
        return _CorpusRetrieval(allowed, hits, ordered_ids, citations)

    def search(self, query: str, *, role: str, limit: int = 5) -> ResearchResult:
        """Ranked, cited, audited free-text search over the whole authorized corpus.

        A sibling of ``_research`` (which answers about a single id): here the free-text
        query is embedded and the scope is the *whole* set the role may see, so results
        span multiple documents. Deterministic (cosine), no fetch, no LLM. Empty results
        are a valid OK (200 at the route), not NOT_FOUND. Exactly one audit record per call.
        """
        rid = uuid.uuid4().hex
        analyst_id = role.strip() or "anonymous"
        now = datetime.now(UTC)
        objective = f'Search corpus for "{query}"'

        # Fail closed if the vector store is unavailable (same contract as _research): one
        # terminal record, FETCH_ERROR, only the exception type. Typed arm then defense-in-depth.
        try:
            r = self._retrieve_corpus(query, role, limit)
        except VectorStoreError as exc:
            self._emit_terminal(
                rid,
                analyst_id,
                objective,
                now,
                f"fetch_error: retrieval failed ({type(exc).__name__})",
            )
            return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)
        except Exception as exc:
            self._emit_terminal(
                rid,
                analyst_id,
                objective,
                now,
                f"fetch_error: retrieval failed ({type(exc).__name__})",
            )
            return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)
        if not r.allowed:
            self._emit_terminal(rid, analyst_id, objective, now, "denied: no corpus retrieved")
            return ResearchResult(Outcome.DENIED, "", [], rid)

        answer = (
            f'{len(r.ordered_ids)} document(s) matched "{query}".'
            if r.ordered_ids
            else f'No documents matched "{query}".'
        )
        emit(
            ResearchRecord(
                research_id=rid,
                analyst_id=analyst_id,
                timestamp=now,
                objective=objective,
                data_source_ids=sorted({self._docs[did].source for did in r.ordered_ids}),
                document_hashes=[self._docs[did].integrity_hash for did in r.ordered_ids],
                model_id="retrieval-only",
                model_version="",
                prompt_template_version="",
                retrieved_doc_ids=r.ordered_ids,
                model_output="\n".join(f"{h.text} [{h.document_id}]" for h in r.hits),
                conclusion=f"retrieval-only: {len(r.ordered_ids)} document(s) from search",
            ),
            self._audit_path,
            key=self._audit_key,
            cipher=self._audit_cipher,
        )
        return ResearchResult(Outcome.OK, answer, r.citations, rid)

    def ask(self, query: str, *, role: str, limit: int = 5) -> ResearchResult:
        """Answer a free-text question with a grounded, cited report over the whole corpus.

        The synthesis sibling of ``search`` (which returns a ranked list): it reuses the shared
        authorize-before-retrieve ``_retrieve_corpus``, then 1a's synthesis seam — the injected
        generator writes over the retrieved passages and ``build_report``'s citation + faithfulness
        gate drops every uncited, non-retrieved, or unfaithful line, so nothing ungrounded reaches
        the caller. The default ``JoinGenerator`` reproduces retrieval-only prose; a configured real
        generator (Ollama) writes grounded answers over the same passages.

        Contracts: authorize before retrieve (a role that may see nothing is DENIED, store never
        queried); an empty retrieval is a valid OK with **no** generator call (nothing to invent
        from); any generator fault — the typed ``GeneratorError`` or any other exception from the
        injected code — fails closed to FETCH_ERROR; exactly one audit record per call, carrying
        the active generator's honest identity.
        """
        rid = uuid.uuid4().hex
        analyst_id = role.strip() or "anonymous"
        now = datetime.now(UTC)
        objective = f'Answer question: "{query}"'

        # Fail closed if the vector store is unavailable (same contract as _research): one
        # terminal record, FETCH_ERROR, only the exception type. Typed arm then defense-in-depth.
        try:
            r = self._retrieve_corpus(query, role, limit)
        except VectorStoreError as exc:
            self._emit_terminal(
                rid,
                analyst_id,
                objective,
                now,
                f"fetch_error: retrieval failed ({type(exc).__name__})",
            )
            return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)
        except Exception as exc:
            self._emit_terminal(
                rid,
                analyst_id,
                objective,
                now,
                f"fetch_error: retrieval failed ({type(exc).__name__})",
            )
            return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)
        if not r.allowed:
            self._emit_terminal(rid, analyst_id, objective, now, "denied: no corpus retrieved")
            return ResearchResult(Outcome.DENIED, "", [], rid)

        if not r.ordered_ids:
            # Empty retrieval is a normal OK, not an error — but the generator is never called on
            # an empty context (no wasted call, nothing to synthesise from). One retrieval-only
            # record; build_report renders "No cited findings." from the empty output.
            record = ResearchRecord(
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
                conclusion="retrieval-only: no documents matched",
            )
            answer = build_report(record)
            emit(record, self._audit_path, key=self._audit_key, cipher=self._audit_cipher)
            return ResearchResult(Outcome.OK, answer, [], rid)

        # Synthesis seam (mirrors _research). The question itself is the generator prompt.
        passages = [f"{hit.text} [{hit.document_id}]" for hit in r.hits]
        gen = self._generator
        try:
            model_output = gen.generate(query, passages)
        except GeneratorError as exc:
            # A real generator failed. Fail closed: one terminal record, FETCH_ERROR, never a
            # silent fallback or a fabricated answer. Only the exception type is recorded.
            self._emit_terminal(
                rid,
                analyst_id,
                objective,
                now,
                f"fetch_error: generation failed ({type(exc).__name__})",
            )
            return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)
        except Exception as exc:
            # Defense in depth: a generator is injected code, so any failure OTHER than the typed
            # GeneratorError must still become FETCH_ERROR with exactly one audit record, never an
            # unhandled 500 with no trail. Only the exception type is recorded (no payload leak).
            self._emit_terminal(
                rid,
                analyst_id,
                objective,
                now,
                f"fetch_error: generation failed ({type(exc).__name__})",
            )
            return ResearchResult(Outcome.FETCH_ERROR, "", [], rid)

        # Audit identity comes from the active generator (honest attribution).
        model_id = getattr(gen, "model_id", "retrieval-only")
        model_version = getattr(gen, "model_version", "")
        prompt_template_version = getattr(gen, "prompt_template_version", "")

        record = ResearchRecord(
            research_id=rid,
            analyst_id=analyst_id,
            timestamp=now,
            objective=objective,
            data_source_ids=sorted({self._docs[did].source for did in r.ordered_ids}),
            document_hashes=[self._docs[did].integrity_hash for did in r.ordered_ids],
            model_id=model_id,
            model_version=model_version,
            prompt_template_version=prompt_template_version,
            retrieved_doc_ids=r.ordered_ids,
            model_output=model_output,
            conclusion=f"{model_id}: assembled from cited passages",
        )
        # Faithfulness floor: build_report drops any surviving line whose claim does not overlap
        # its cited passage text — catches a valid-id line with invented content.
        passages_by_id = {
            did: [hit.text for hit in r.hits if hit.document_id == did] for did in r.ordered_ids
        }
        answer = build_report(record, passages_by_id)
        emit(record, self._audit_path, key=self._audit_key, cipher=self._audit_cipher)
        return ResearchResult(Outcome.OK, answer, r.citations, rid)

    def _emit_terminal(
        self,
        rid: str,
        analyst_id: str,
        objective: str,
        now: datetime,
        conclusion: str,
    ) -> None:
        record = ResearchRecord(
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
        )
        try:
            emit(record, self._audit_path, key=self._audit_key, cipher=self._audit_cipher)
        except Exception as exc:
            # Terminal (DENIED/NOT_FOUND/FETCH_ERROR) audit path: a second exception here would
            # surface as an unhandled 500 on a request we have already decided to fail. Log the
            # failure type only (never record content) and let the terminal result stand.
            logging.getLogger("secure_ai_research.audit").error(
                "terminal audit emit failed: %s", type(exc).__name__
            )
