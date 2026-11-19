# `POST /research/search` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the `POST /research/search` 501 stub into a real, ranked, cited, audited free-text semantic search over the whole authorized corpus.

**Architecture:** A new sibling method `ResearchService.search()` reuses the existing embedder / vector-store / authz / audit primitives — it embeds the *free-text query*, scopes the store query to the *whole* set the role may see, applies a `score > 0` relevance floor, dedups to the best passage per document, and emits exactly one audit record. `_research` and the two id-routes are left untouched. A `SearchRequest`-validated POST route serializes the ranked citations with a 1-based `rank`.

**Tech Stack:** Python 3.12, FastAPI, pydantic, stdlib only (no new runtime dependency).

**Spec:** `docs/superpowers/specs/2026-11-19-phase2-search-endpoint-design.md`

## Global Constraints

- **stdlib-only, no new runtime dependency.** Deterministic (cosine via `HashingEmbedder`), offline.
- Tests hermetic — no network outside `@pytest.mark.integration` (there is none here).
- PUBLIC/synthetic corpus only.
- **Reuse `ResearchResult` and `Citation` unchanged; do NOT modify `_research` or the id-routes** (`/cve`, `/attack`) — search is purely additive.
- `X-Role` is the Phase-1 self-asserted spoofable dev stub; the route carries the same SECURITY docstring as the other two; no real-network exposure until Phase-5 OIDC.
- `ruff`/`black`/`mypy` clean; line length 100.
- Every commit ends with the attribution footer:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU`.

## Review Focus

1. **Scope = whole `allowed` set** (not `allowed & {id}`): results span multiple documents and sources, and a present-but-unauthorized document never appears — Task 1 `test_search_ranks_across_sources`, `test_search_excludes_unauthorized_documents`.
2. **Empty result (query shares no token with any authorized doc, after the `score > 0` floor) → OK 200 + exactly one audit record** — Task 1 `test_search_no_match_is_ok_empty`.
3. **Malformed/oversized query or `limit` out of 1..20 → 422 with ZERO audit records** (validation runs before the handler) — Task 2 `test_search_blank_query_422_no_audit`, `test_search_oversized_query_422`, `test_search_limit_out_of_range_422`.
4. **`_research` and the two id-routes are behavior-unchanged** (additive change) — pinned by the pre-existing CVE/ATT&CK tests staying green in the full suite; no new test.
5. **No raw cosine `score` in the response — `rank` only** — Task 2 `test_search_200_has_rank_not_score` (`Citation` carries no score field, so this is structural; the test guards it).

---

### Task 1: `ResearchService.search()`

**Files:**
- Modify: `src/secure_ai_research/research_service.py` (add one method; touch nothing else)
- Test: `tests/test_research_service.py`

**Interfaces:**
- Consumes: `self._snapshot()`, `self._authorize`, `self._embedder.embed`, `self._store.query(vec, allowed_document_ids=..., limit=...)` returning `ChunkHit(document_id, text, score)`, `Citation`, `ResearchResult`, `Outcome`, `ResearchRecord`, `emit`, `self._emit_terminal` — all already imported/defined in the module.
- Produces: `search(self, query: str, *, role: str, limit: int = 5) -> ResearchResult` with `outcome ∈ {OK, DENIED}`; on OK, `citations` is the ranked best-passage-per-document list (list order **is** the rank) and `answer` is a one-line summary.

- [ ] **Step 1: Write the failing tests** in `tests/test_research_service.py`

Add helpers (reuse existing imports; add one new import `from secure_ai_research.retrieval.ports import ChunkHit`):

```python
def _mk(doc_id, source, source_url, text):
    doc = ResearchDocument(
        document_id=doc_id, source=source, document_type=DocumentType.VULNERABILITY,
        classification=Classification.PUBLIC, created_at=date(2099, 1, 1),
        source_url=source_url, integrity_hash="sha256:" + "0" * 64,  # type: ignore[arg-type]
    )
    return IngestedDocument(doc, text)

def _search_svc(audit, authorize_fn=authorize):
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize_fn, audit)
    svc.index([
        _mk("CVE-2099-0001", "NVD", "https://nvd.nist.gov/vuln/detail/CVE-2099-0001", "widget widget widget"),
        _mk("T1059", "MITRE ATT&CK", "https://attack.mitre.org/techniques/T1059/", "widget alpha"),
    ])
    return svc

class _ZeroScoreStore(InMemoryVectorStore):
    def query(self, embedding, *, allowed_document_ids, limit):
        return [ChunkHit(did, "irrelevant", 0.0) for did in sorted(allowed_document_ids)][:limit]
```

Tests:

```python
def test_search_ranks_across_sources(tmp_path):
    audit = tmp_path / "a.jsonl"
    res = _search_svc(audit).search("widget", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert [c.document_id for c in res.citations] == ["CVE-2099-0001", "T1059"]  # 3×widget ranks first
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
    svc.index([_mk("CVE-2099-0001", "NVD", "https://nvd.nist.gov/vuln/detail/CVE-2099-0001", "widget")])
    res = svc.search("widget", role="")
    assert res.outcome is Outcome.DENIED
    assert res.citations == []
    assert spy.query_calls == 0
    assert read_records(audit)[0].retrieved_doc_ids == []

def test_search_no_match_is_ok_empty(tmp_path):
    audit = tmp_path / "a.jsonl"
    svc = ResearchService(HashingEmbedder(), _ZeroScoreStore(), authorize, audit)
    svc.index([_mk("CVE-2099-0001", "NVD", "https://nvd.nist.gov/vuln/detail/CVE-2099-0001", "widget")])
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
    assert [c.document_id for c in res.citations] == ["CVE-2099-0001"]  # one entry despite many chunks
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_research_service.py -k search -q`
Expected: FAIL — `ResearchService` has no attribute `search` (AttributeError).

- [ ] **Step 3: Implement `search`** in `src/secure_ai_research/research_service.py`

Add this method (mirrors the `_research` OK-tail; no new imports; `_research` untouched):

```python
def search(self, query: str, *, role: str, limit: int = 5) -> ResearchResult:
    """Ranked, cited, audited free-text search over the whole authorized corpus.

    Deterministic (cosine), no fetch, no LLM. Empty results are a valid OK (200 at the
    route), not NOT_FOUND. Exactly one audit record per call.
    """
    rid = uuid.uuid4().hex
    analyst_id = role.strip() or "anonymous"
    now = datetime.now(UTC)
    objective = f'Search corpus for "{query}"'

    allowed = {did for did, doc in self._snapshot() if self._authorize(role, doc)}
    if not allowed:
        self._emit_terminal(rid, analyst_id, objective, now, "denied: no corpus retrieved")
        return ResearchResult(Outcome.DENIED, "", [], rid)

    hits = [
        h
        for h in self._store.query(
            self._embedder.embed([query])[0], allowed_document_ids=allowed, limit=limit
        )
        if h.score > 0  # relevance floor: drop zero-score (no shared token) hits
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
    answer = (
        f'{len(ordered_ids)} document(s) matched "{query}".'
        if ordered_ids
        else f'No documents matched "{query}".'
    )
    emit(
        ResearchRecord(
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
            model_output="\n".join(f"{h.text} [{h.document_id}]" for h in hits),
            conclusion=f"retrieval-only: {len(ordered_ids)} document(s) from search",
        ),
        self._audit_path,
    )
    return ResearchResult(Outcome.OK, answer, citations, rid)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_research_service.py -q`
Expected: PASS (all search tests + the pre-existing service tests).

- [ ] **Step 5: Commit**

```bash
git add src/secure_ai_research/research_service.py tests/test_research_service.py
git commit   # feat(service): ranked corpus search via ResearchService.search  (+ footer)
```

---

### Task 2: Wire `POST /research/search`

**Files:**
- Modify: `src/secure_ai_research/api/routers/research.py` (add `SearchRequest`, replace the `/search` 501 stub, drop the now-unused `_NOT_IMPLEMENTED`, update the module docstring)
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `service.search(query, *, role, limit) -> ResearchResult` (Task 1); `Citation` fields via `asdict`.
- Produces: `POST /research/search`.

- [ ] **Step 1: Write the failing tests** in `tests/test_api.py`

Add a helper and tests (needed imports — `ResearchService`, `HashingEmbedder`, `InMemoryVectorStore`, `authorize`, `ResearchDocument`, `IngestedDocument`, `DocumentType`, `Classification`, `date`, `app`, `client`, `get_service`, `read_records` — should already be present from the prior slices; add `import pytest` if absent, for the parametrized limit test):

```python
def _override_search_service(tmp_path):
    audit = tmp_path / "audit.jsonl"
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit)
    svc.index([
        IngestedDocument(ResearchDocument(
            document_id="CVE-2099-0001", source="NVD", document_type=DocumentType.VULNERABILITY,
            classification=Classification.PUBLIC, created_at=date(2099, 1, 1),
            source_url="https://nvd.nist.gov/vuln/detail/CVE-2099-0001",  # type: ignore[arg-type]
            integrity_hash="sha256:" + "0" * 64), "widget widget widget"),
        IngestedDocument(ResearchDocument(
            document_id="T1059", source="MITRE ATT&CK", document_type=DocumentType.TECHNIQUE,
            classification=Classification.PUBLIC, created_at=date(2017, 5, 31),
            source_url="https://attack.mitre.org/techniques/T1059/",  # type: ignore[arg-type]
            integrity_hash="sha256:" + "0" * 64), "widget alpha"),
    ])
    app.dependency_overrides[get_service] = lambda: svc
    return audit

def test_search_200_has_rank_not_score(tmp_path):
    _override_search_service(tmp_path)
    resp = client.post("/research/search", json={"query": "widget"}, headers={"X-Role": "research_analyst"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] == "widget" and body["count"] == len(body["results"]) and body["research_id"]
    first = body["results"][0]
    assert first["rank"] == 1 and first["document_id"] == "CVE-2099-0001" and "passage" in first
    assert "source_url" in first and "score" not in first

def test_search_missing_role_denied(tmp_path):
    _override_search_service(tmp_path)
    assert client.post("/research/search", json={"query": "widget"}).status_code == 403

def test_search_blank_query_422_no_audit(tmp_path):
    audit = _override_search_service(tmp_path)
    resp = client.post("/research/search", json={"query": "   "}, headers={"X-Role": "research_analyst"})
    assert resp.status_code == 422
    assert not audit.exists()  # validation rejected before the handler → zero audit records

def test_search_oversized_query_422(tmp_path):
    _override_search_service(tmp_path)
    resp = client.post("/research/search", json={"query": "x" * 513}, headers={"X-Role": "research_analyst"})
    assert resp.status_code == 422

@pytest.mark.parametrize("bad_limit", [0, 21])
def test_search_limit_out_of_range_422(tmp_path, bad_limit):
    _override_search_service(tmp_path)
    resp = client.post(
        "/research/search",
        json={"query": "widget", "limit": bad_limit},
        headers={"X-Role": "research_analyst"},
    )
    assert resp.status_code == 422
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_api.py -k search -q`
Expected: FAIL — the stub returns 501 (and there is no body validation yet).

- [ ] **Step 3: Replace the stub** in `src/secure_ai_research/api/routers/research.py`

Add imports `from typing import Annotated` and `from pydantic import BaseModel, Field, StringConstraints`. Define the body model and the route; drop the now-unused `_NOT_IMPLEMENTED` constant and update the module docstring (all three `/research/*` routes are now live).

```python
class SearchRequest(BaseModel):
    query: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)]
    limit: int = Field(default=5, ge=1, le=20)


@router.post("/search")
def research_search(
    req: SearchRequest,
    x_role: str = Header(default=""),
    service: ResearchService = Depends(get_service),
) -> JSONResponse:
    """Ranked, cited search over the authorized corpus.

    SECURITY: ``X-Role`` is a Phase-1 self-asserted development stub, not an
    authentication control — a client sets it freely (threat T1). Phase 5 replaces it
    with verified OIDC roles. Do not expose this route on a real network until then.
    """
    res = service.search(req.query, role=x_role, limit=req.limit)
    if res.outcome is Outcome.DENIED:
        return JSONResponse(
            status_code=403,
            content={"detail": "role not authorized", "research_id": res.research_id},
        )
    results = [{"rank": i + 1, **asdict(c)} for i, c in enumerate(res.citations)]
    return JSONResponse(
        status_code=200,
        content={
            "query": req.query,
            "count": len(results),
            "results": results,
            "research_id": res.research_id,
        },
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_api.py -q`
Expected: PASS (search tests + the pre-existing cve/attack/health/version tests).

- [ ] **Step 5: Commit**

```bash
git add src/secure_ai_research/api/routers/research.py tests/test_api.py
git commit   # feat(api): wire POST /research/search (ranked cited results)  (+ footer)
```

---

## Final checks (before review)

- [ ] `.venv/bin/pytest -q` — full suite green (hermetic).
- [ ] `.venv/bin/ruff check .` && `.venv/bin/black --check .` && `.venv/bin/mypy` — clean.
