# Phase 2 — `POST /research/search` endpoint design

**Status:** approved (Chris, 2026-11-19 — chose return-shape **A**, build **Approach 1**, as part of the "run all Phase 2 in-posture" batch).
**Slice 1 of the in-posture Phase-2 completion batch** (search → CISA KEV → Sigma → end-to-end demo).

## 1. Intent / why

`POST /research/search` is the third and last retrieval surface of Phase 2, after
`GET /research/cve/{id}` and `GET /research/attack/{id}`. Those answer "tell me about
*this* identifier"; search answers "find me what in the corpus matches *this free-text
query*." It turns the standing 501 stub into a real, cited, audited **ranked search**
over the whole authorized corpus (today: NVD + MITRE ATT&CK; soon KEV + Sigma from the
sibling slices), so an analyst can discover evidence by topic rather than only by id.

## 2. Goals

- Free-text query → **ranked list of matching passages** across the whole authorized
  corpus, deduplicated to the **best passage per document**, each result carrying
  `rank` (1-based), `document_id`, `source_url`, `passage`.
- **Authorize-before-retrieve**: the scope passed into the store query is the full set
  of documents the caller's role may see; a document outside it is never queried and
  cannot appear in results (same gate as the id-routes, document-type agnostic).
- **Deterministic** ranking (cosine via the existing `HashingEmbedder`), **no LLM**,
  **offline/hermetic**, **stdlib-only** (no new runtime dependency).
- **Exactly one audit record per request**, including a zero-hit search.

## 3. Non-goals

- No synthesized narrative answer — that is what `/cve` and `/attack` already do.
  `answer` here is a thin deterministic summary line only.
- No fetch-on-miss and **no 503**: search never reaches off-box (it ranks what is
  already indexed).
- **No raw score exposed.** `ChunkHit.score` exists internally and orders the results,
  but a cosine from a 256-dim bag-of-words embedder is not a meaningful relevance
  percentage; surfacing it invites false precision. Results carry `rank` only.
- No per-chunk results: a document appears at most once (best passage). (If multiple
  passages per document are ever wanted, that is a follow-up, not this slice.)
- No cross-source correlation/boosting beyond plain cosine nearest-neighbour.
- No new infrastructure (pgvector / MinIO / Ollama) — deliberately deferred behind the
  existing `Embedder` / `VectorStore` Protocol seams.

## 4. Anti-goals (a failure even if it "works")

- **Scope leak / existence oracle:** a document the role may not see appears in results,
  or a role-dependent difference reveals a document's existence. Search must only ever
  query within `allowed`; an unauthorized caller gets DENIED with no corpus metadata.
- **Citation integrity break:** a returned `passage` that is not actually the text of
  the cited `document_id`, or a `source_url` that does not belong to it.
- **Audit-invariant break:** more than one audit record, or zero on any path (including
  empty results and DENIED).
- **A malformed or oversized query crashing** (500) instead of a clean 422.

## 5. Constraints

- Python 3.12, **stdlib-only**, no new runtime dependency. Deterministic, offline.
- PUBLIC/synthetic only. Tests hermetic (no network outside `@pytest.mark.integration`).
- `X-Role` is the Phase-1 self-asserted dev stub (spoofable; threat T1); Phase-5 OIDC
  replaces it. Do not expose on a real network until then. Route carries the SECURITY
  docstring like the two existing routes.
- `ruff`/`black`/`mypy` clean; line length 100. Attribution footer on every commit.

## 6. Approaches considered

- **Approach 1 — new sibling method `ResearchService.search(...)` (CHOSEN).** Add a
  `search(query, *, role, limit)` method that reuses the existing primitives — compute
  `allowed` via `_snapshot()` + `_authorize` exactly as `_research` does, embed the
  *query text* (not an id), `store.query(qvec, allowed_document_ids=allowed, limit)`,
  dedup to best passage per document, emit one `ResearchRecord`, reuse `_emit_terminal`
  for the DENIED path. **`_research` is left entirely untouched** (the final reviewer
  just verified the CVE path is behavior-unchanged; this keeps it so). Cost: a small
  repeat of the `rid`/`now`/`allowed` boilerplate — acceptable.
- **Approach 2 — extract a shared helper** for the `allowed`-set + record-emit
  boilerplate, adopted by both `_research` and `search`. Removes the small duplication
  but **re-opens `_research`**, adding risk and review surface for little gain.
- **Approach 3 — generalize `_research`** to take a free-text query, an arbitrary scope,
  and pluggable empty-result semantics. Most unified but **worst risk**: it mixes two
  different "nothing found" meanings (id-miss → 404 vs search-empty → 200-empty) into the
  one method the whole app depends on. Rejected.

**Why Approach 1:** search's semantics differ enough from the id-routes (free-text query,
whole-corpus scope, empty-is-a-valid-200) that a clean separate path is simpler and safer
than overloading the proven `_research`.

## 7. The design (decided)

### 7.1 Request / response (route)

- `POST /research/search`, JSON body `SearchRequest`, header `X-Role` (default `""`),
  returns `JSONResponse`.
- `SearchRequest` (pydantic): `query: str` (strip; after strip must be non-empty and
  ≤ 512 chars), `limit: int = 5` (bounded **1..20**). A violation is a **422** raised by
  pydantic validation **before** the handler body — so no service call and no audit
  record on a malformed request (mirrors the id-routes' `Path(pattern=...)` → 422).
- Outcomes → status:
  - `OK` → **200** `{"query": <str>, "count": <int>, "results": [{"rank","document_id","source_url","passage"}...], "research_id": <hex>}`. **Empty results are OK → 200** with `results: []`, `count: 0`.
  - `DENIED` → **403** `{"detail": "role not authorized", "research_id": <hex>}`.
  - No `NOT_FOUND`/`FETCH_ERROR` branch exists on this route.

### 7.2 Service (`ResearchService.search`)

Signature: `search(self, query: str, *, role: str, limit: int = 5) -> ResearchResult`.
Returns the existing `ResearchResult` (reused, not a new type): `answer` = the thin
summary line, `citations` = the ranked best-passage-per-document list (order **is** the
rank), `research_id`, `outcome` ∈ {OK, DENIED}.

Flow:
1. `rid`, `analyst_id = role.strip() or "anonymous"`, `now`.
2. `allowed = {did for did, doc in self._snapshot() if self._authorize(role, doc)}`.
3. If `not allowed` → `_emit_terminal(..., "denied: no corpus retrieved")`, return
   `ResearchResult(DENIED, "", [], rid)`.
4. `qvec = self._embedder.embed([query])[0]`;
   `hits = self._store.query(qvec, allowed_document_ids=allowed, limit=limit)`.
4b. **Relevance floor — keep only `hit.score > 0`.** The embedder yields cosine `0`
   exactly when the query shares no token with the chunk, but the store returns a flat
   top-`limit` that *includes* zero-score chunks. A search must not return non-matching
   junk, and "nothing matched" must be a real empty result — so `search()` drops
   zero-score hits itself. This lives in `search()`, **not** the shared store, so
   `_research` and the id-routes are unaffected. (`limit` therefore bounds the *chunks*
   scanned, exactly as in `_research`; the distinct documents among the surviving hits
   are the results, so a result set can be smaller than `limit` — a deliberate
   simplification for this slice, noted in §8.)
5. Dedup the surviving hits to best passage per document, preserving hit order (same
   `ordered_ids` / `first_text` logic as `_research`): build `citations = [Citation(did,
   str(self._docs[did].source_url), first_text[did]) for did in ordered_ids]`.
6. `objective = f'Search corpus for "{query}"'`; `answer = f'{len(ordered_ids)} document(s)
   matched "{query}".'` (empty → `f'No documents matched "{query}".'`).
7. Emit **one** `ResearchRecord`: `retrieved_doc_ids = ordered_ids`,
   `data_source_ids = sorted({...source})`, `document_hashes = [...integrity_hash]`,
   `model_id = "retrieval-only"`, `model_output = "\n".join(f"{t} [{did}]")`,
   `conclusion = f'retrieval-only: {len(ordered_ids)} document(s) from search'`. Emit
   even when empty (empty lists / zero-doc conclusion) — the one-record invariant holds.
8. Return `ResearchResult(OK, answer, citations, rid)`.

### 7.3 Rank at the edge

`Citation` is not extended (it is shared with `/cve` and `/attack`). The route serializes
each citation with its 1-based position: `{"rank": i + 1, **asdict(c)}`. `source_url`
already identifies the source (e.g. `attack.mitre.org` vs the NVD url); no separate
`source` field is added in this slice.

## 8. What is left to the builder

- The `SearchRequest` pydantic model with the `query`/`limit` field constraints and the
  strip-then-validate for `query`.
- The best-passage-per-document dedup in `search` (reuse the `_research` idiom), applied
  after the `score > 0` relevance floor.
- Known simplification (not a bug): `limit` bounds the chunks scanned, so a result set
  can have fewer than `limit` documents when several top chunks share a document.
- Test cases across layers (service: OK ranked+deduped, DENIED, empty→OK-empty, one audit
  record each; api: 200 shape with `rank`, 403 missing role, 422 empty/oversized
  query and out-of-range limit, empty-query-zero-audit-records; a cross-source result
  once ATT&CK + NVD are both indexed via the real `get_service`).

## 9. Review focus (for the final reviewer)

1. **Scope = whole `allowed` set** (not `allowed & {something}`): results may span
   multiple documents and sources; a present-but-unauthorized doc never appears.
2. **Empty result is 200, not 404** (a query sharing no token with any authorized doc,
   after the `score > 0` floor), and still writes exactly one audit record.
3. **422 (malformed/oversized query, limit out of 1..20) writes zero audit records**
   (validation is before the handler body).
4. **`_research` and the two id-routes are behavior-unchanged** (search is additive).
5. **No raw score leaks** into the response; `rank` reflects the store's cosine order.
