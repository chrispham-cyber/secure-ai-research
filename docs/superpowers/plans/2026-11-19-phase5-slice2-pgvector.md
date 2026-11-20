# Phase 5 Slice 2 — pgvector VectorStore Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (Native/continuous, chosen by Chris). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a real Postgres/pgvector `VectorStore` adapter behind the existing Protocol, opt-in and fail-closed, with the default `memory` path byte-identical.

**Architecture:** `PgVectorStore` (lazy `psycopg`/`pgvector`, exact cosine via `<=>`, scope as a SQL `WHERE` predicate, idempotent `ON CONFLICT` upsert) selected by `SAIR_VECTOR_STORE=pgvector` through a new `make_vector_store` factory; a new typed `VectorStoreError` makes any store fault fail closed to `FETCH_ERROR` + exactly one audit record, surfaced as 503 on every route. Parity with `InMemoryVectorStore` is a hard equality because the deterministic `HashingEmbedder` is unchanged.

**Tech Stack:** Python 3.12, FastAPI, pydantic-settings, `psycopg[binary]` 3.2+ & `pgvector` 0.3+ (optional extra only), pytest (hermetic default + `-m integration`).

**Spec:** `docs/superpowers/specs/2026-11-19-phase5-slice2-pgvector-design.md`

## Global Constraints

- Python ≥ 3.12; run via `./.venv/bin/python` / `./.venv/bin/pytest`.
- **PUBLIC / synthetic data only;** never commit secrets or a `.env`. Dev creds `sair:sair@localhost` are documented local-dev placeholders.
- **No new *default* runtime dependency.** `psycopg`/`pgvector` enter ONLY as `[project.optional-dependencies].pgvector`, lazily imported inside the adapter; the hermetic suite must never import `psycopg`.
- Default run is hermetic: `addopts = ["-m", "not integration"]`. Real pg only under `-m integration`, which must SKIP cleanly when Postgres is unreachable or the extra is absent.
- **Exactly one audit record per request on every path** (the invariant).
- Default `SAIR_VECTOR_STORE=memory` ⇒ behavior and bytes identical to main@6a7eb74; the Phase-4 `1.0` regression gate stays green.
- TDD throughout; attribution footer on commits; **local only, no push.**

## Review Focus

1. **Store failure mid-request on every route** — a pg outage after boot must become **503 + exactly one audit record** on `cve`/`attack`/`search`/`ask`, never an unhandled 500 nor a masked 404/empty-200. → Task 1 (service FETCH_ERROR+one-record via a raising fake) + Task 2 (router `attack`/`search` 503).
2. **Cosine distance vs similarity sign error** — pgvector `<=>` is distance; a missing `1 - d` inverts ranking and breaks the `score > 0` floor. → Task 4 (integration parity + "query == chunk ⇒ score ≈ 1.0").
3. **Scope not enforced in SQL** — scope applied post-query or omitted lets an unauthorized doc rank in. → Task 4 (integration scope-as-SQL predicate test).
4. **Non-idempotent re-index** — missing `ON CONFLICT (chunk_id) DO UPDATE` duplicates chunks every boot. → Task 4 (integration upsert-twice row-count).
5. **Extra selected but not installed / default suite imports psycopg** — must fail loud with a clear remediation message, and importing the module must not import `psycopg`. → Task 4 (hermetic "module import does not import psycopg" + clear-error path) + Task 3 (factory default = InMemory).

---

### Task 1: `VectorStoreError` + fail-closed store wiring in the service

**Files:**
- Modify: `src/secure_ai_research/retrieval/ports.py` (add `VectorStoreError`)
- Modify: `src/secure_ai_research/research_service.py` (wrap the 3 store-query sites)
- Test: `tests/test_store_failclosed.py` (create)

**Interfaces:**
- Produces: `class VectorStoreError(Exception)` in `secure_ai_research.retrieval.ports` (consumed by Task 4's adapter and by the service's typed `except`).
- Consumes: existing `ResearchService.search/ask/research_cve`, `Outcome.FETCH_ERROR`, `_emit_terminal`, the audit log file.

- [ ] **Step 1: Write the failing test** `tests/test_store_failclosed.py`

```python
# Fakes implement the VectorStore Protocol; upsert is a no-op so _docs still populates,
# query raises so the request-time path trips the fail-closed wrapper.
class _RaisingTypedStore:           # raises the typed error
    def upsert(self, entries): ...
    def query(self, embedding, *, allowed_document_ids, limit):
        raise VectorStoreError("pg down")

class _RaisingBroadStore:           # defense-in-depth arm: a non-typed error
    def upsert(self, entries): ...
    def query(self, embedding, *, allowed_document_ids, limit):
        raise RuntimeError("socket closed")

def _service(store, audit_path):    # HashingEmbedder + authorize + one NVD fixture indexed
    svc = ResearchService(HashingEmbedder(), store, authorize, audit_path)
    svc.index(nvd.load(_nvd_sample_bytes()))
    return svc

def _audit_lines(p): return [l for l in p.read_text().splitlines() if l.strip()]

@pytest.mark.parametrize("store_cls", [_RaisingTypedStore, _RaisingBroadStore])
@pytest.mark.parametrize("call", [
    lambda s: s.search("sql injection", role="research_analyst"),
    lambda s: s.ask("sql injection", role="research_analyst"),
    lambda s: s.research_cve("CVE-2099-0001", role="research_analyst"),  # id present in nvd_sample
])
def test_store_failure_is_fetch_error_with_one_audit_record(tmp_path, store_cls, call):
    audit = tmp_path / "audit.jsonl"
    res = call(_service(store_cls(), audit))
    assert res.outcome is Outcome.FETCH_ERROR
    assert res.answer == "" and res.citations == []
    assert len(_audit_lines(audit)) == 1            # exactly one record
    assert "pg down" not in audit.read_text()       # no payload leak (type only)

def test_denied_role_never_reaches_store_no_fetch_error(tmp_path):
    # a role authorized for nothing is DENIED, store never queried (no FETCH_ERROR)
    res = _service(_RaisingTypedStore(), tmp_path / "a.jsonl").search("x", role="")
    assert res.outcome is Outcome.DENIED
```

- [ ] **Step 2: Run to verify it fails** — `./.venv/bin/pytest tests/test_store_failclosed.py -q`
  Expected: FAIL — `VectorStoreError` not importable / store exceptions propagate (not `FETCH_ERROR`). Confirm the NVD fixture id used (`CVE-2099-0001`/`0002`) matches `ingestion/samples/nvd_sample.json` before relying on the id-route case; adjust the literal if the fixture differs.

- [ ] **Step 3: Add `VectorStoreError`** to `retrieval/ports.py`:
```python
class VectorStoreError(Exception):
    """Raised by a VectorStore adapter when the backing store is unavailable or fails."""
```

- [ ] **Step 4: Wrap the three store-query sites** in `research_service.py`, importing `VectorStoreError` from `.retrieval.ports`. Mirror the generator path's two-arm style (typed then defense-in-depth), each emitting exactly one terminal record and recording only `type(exc).__name__`:
  - `_research`: wrap the `hits = self._store.query(...)` call (~line 209).
  - `search`: wrap the `r = self._retrieve_corpus(query, role, limit)` call.
  - `ask`: wrap the `r = self._retrieve_corpus(query, role, limit)` call.
  Conclusion string: `f"fetch_error: retrieval failed ({type(exc).__name__})"`. Return `ResearchResult(Outcome.FETCH_ERROR, "", [], rid)`. The DENIED checks stay after the wrapped retrieval (a DENIED role never queries the store, so it is unaffected).

- [ ] **Step 5: Run to verify it passes** — `./.venv/bin/pytest tests/test_store_failclosed.py -q` → PASS.

- [ ] **Step 6: Run the whole hermetic suite** — `./.venv/bin/pytest -q -m "not integration"` → all green (InMemory never raises, so existing search/ask/cve behavior is unchanged).

- [ ] **Step 7: Commit** — `feat(service): fail-closed VectorStoreError → FETCH_ERROR with one audit record (Slice 2)`

---

### Task 2: Router surfaces a store outage as 503 on `attack` and `search`

**Files:**
- Modify: `src/secure_ai_research/api/routers/research.py` (`research_attack`, `research_search` + their docstrings)
- Test: `tests/test_api.py` (append)

**Interfaces:**
- Consumes: `Outcome.FETCH_ERROR` now reachable from `search`/`research_attack` (Task 1).
- Produces: `attack`/`search` routes mapping `FETCH_ERROR→503 {"detail":"upstream source unavailable", "research_id":…}` (same shape as `cve`/`ask`).

- [ ] **Step 1: Write the failing test** (`tests/test_api.py`) — override the service dependency with a stub whose `search`/`research_attack` return `ResearchResult(Outcome.FETCH_ERROR, "", [], "rid")`, then:
```python
def test_search_store_failure_is_503(): ...   # POST /research/search → 503, detail "upstream source unavailable"
def test_attack_store_failure_is_503(): ...    # GET /research/attack/T1059 → 503
```

- [ ] **Step 2: Run to verify it fails** — `./.venv/bin/pytest tests/test_api.py -q -k "store_failure"`
  Expected: FAIL — `search` returns 200 (empty), `attack` returns 404 (no FETCH_ERROR branch today).

- [ ] **Step 3: Add the branches.** In `research_attack`, before the final 404, add `if res.outcome is Outcome.FETCH_ERROR: return JSONResponse(503, {"detail":"upstream source unavailable","research_id":res.research_id})`. In `research_search`, add the same branch after the DENIED check and before the 200. Update both docstrings (attack: drop "no 503 path here"; search: "no 404; 503 only when the store is unavailable").

- [ ] **Step 4: Run to verify it passes** — `./.venv/bin/pytest tests/test_api.py -q` → PASS (new + existing).

- [ ] **Step 5: Commit** — `feat(api): 503 on attack/search when the vector store is unavailable (Slice 2)`

---

### Task 3: `vector_store` setting + `make_vector_store` factory + deps wiring

**Files:**
- Modify: `src/secure_ai_research/config.py` (add `vector_store`)
- Create: `src/secure_ai_research/retrieval/factory.py`
- Modify: `src/secure_ai_research/api/deps.py` (use the factory)
- Test: `tests/test_vector_store_factory.py` (create)

**Interfaces:**
- Produces: `make_vector_store(settings: Settings) -> VectorStore` (consumed by `deps`); `Settings.vector_store: Literal["memory","pgvector"]`.
- Consumes: `InMemoryVectorStore`, `PgVectorStore` (stub until Task 4 — only referenced on the pgvector branch, never constructed hermetically).

- [ ] **Step 1: Write the failing test** `tests/test_vector_store_factory.py`:
```python
def test_default_is_in_memory():
    assert isinstance(make_vector_store(Settings(vector_store="memory")), InMemoryVectorStore)

def test_pgvector_setting_parses_from_env(monkeypatch):
    monkeypatch.setenv("SAIR_VECTOR_STORE", "pgvector")
    assert Settings().vector_store == "pgvector"

def test_default_settings_select_memory():
    assert Settings().vector_store == "memory"     # unchanged default
```

- [ ] **Step 2: Run to verify it fails** — `./.venv/bin/pytest tests/test_vector_store_factory.py -q`
  Expected: FAIL — `vector_store` not on `Settings`; `make_vector_store` undefined.

- [ ] **Step 3: Implement.**
  - `config.py`: add `vector_store: Literal["memory", "pgvector"] = "memory"`.
  - `retrieval/factory.py` (mirror `generation/factory.py`):
```python
def make_vector_store(settings: Settings) -> VectorStore:
    if settings.vector_store == "pgvector":
        from secure_ai_research.retrieval.vectorstore import PgVectorStore
        return PgVectorStore(settings.db_url)
    return InMemoryVectorStore()
```
  (Import `PgVectorStore` lazily inside the branch so the default path and the hermetic suite never touch it.)
  - `deps.py`: replace `InMemoryVectorStore()` with `make_vector_store(settings)`; drop the now-unused direct import if appropriate.

- [ ] **Step 4: Run to verify it passes** — `./.venv/bin/pytest tests/test_vector_store_factory.py -q` → PASS.

- [ ] **Step 5: Run the hermetic suite** — `./.venv/bin/pytest -q -m "not integration"` → green (default still InMemory; existing API tests untouched).

- [ ] **Step 6: Commit** — `feat(config): SAIR_VECTOR_STORE + make_vector_store factory, default memory (Slice 2)`

---

### Task 4: `PgVectorStore` adapter + optional extra (hermetic guards + integration tests)

**Files:**
- Modify: `pyproject.toml` (`[project.optional-dependencies].pgvector`)
- Modify: `src/secure_ai_research/retrieval/vectorstore.py` (replace the stub)
- Modify: `tests/test_stubs.py` (retire the `PgVectorStore` entry; `OllamaEmbedder` stays)
- Modify: `ROADMAP.md` (honest partial tick)
- Test: `tests/test_pgvector_adapter.py` (create, hermetic guards) + `tests/test_integration_pgvector.py` (create, `-m integration`)

**Interfaces:**
- Consumes: `VectorStoreError` (Task 1), `ChunkRecord`/`ChunkHit` (ports), `HashingEmbedder`, `InMemoryVectorStore` (parity target), `settings.db_url`.
- Produces: `PgVectorStore(dsn: str)` implementing `VectorStore` (`upsert`, `query`).

- [ ] **Step 1: Add the extra** to `pyproject.toml`:
```toml
[project.optional-dependencies]
pgvector = ["psycopg[binary]>=3.2", "pgvector>=0.3"]
```
  (Keep any existing extras; add this group.)

- [ ] **Step 2: Write the HERMETIC guard tests** `tests/test_pgvector_adapter.py`. These must hold **whether or not** the `pgvector` extra is installed (Task 4 step 8 installs it in the same venv for the integration run), so the "missing extra" case simulates absence by monkeypatching the import rather than depending on psycopg being uninstalled:
```python
def test_importing_vectorstore_does_not_import_psycopg():
    # lazy-import posture: the module's top level must not pull psycopg in.
    import importlib, sys
    if "psycopg" in sys.modules:
        pytest.skip("psycopg already loaded by another test in this process")
    sys.modules.pop("secure_ai_research.retrieval.vectorstore", None)
    importlib.import_module("secure_ai_research.retrieval.vectorstore")
    assert "psycopg" not in sys.modules      # proves the import is inside __init__, not module-level

def test_missing_extra_raises_clear_vector_store_error(monkeypatch):
    # Force ImportError for psycopg regardless of whether it is installed, proving the
    # adapter fails loud with a remediation message (not a bare ImportError, not silent).
    import builtins
    real_import = builtins.__import__
    def fake_import(name, *a, **k):
        if name == "psycopg" or name.startswith("psycopg"):
            raise ImportError("No module named 'psycopg'")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(VectorStoreError) as exc:
        PgVectorStore("postgresql://sair:sair@localhost:5432/sair")
    assert "pgvector" in str(exc.value).lower()   # names the extra to install

def test_stub_test_retired():
    # test_stubs now covers only OllamaEmbedder (PgVectorStore is real)
    ...
```

- [ ] **Step 3: Run to verify they fail** — `./.venv/bin/pytest tests/test_pgvector_adapter.py tests/test_stubs.py -q`
  Expected: FAIL — stub still raises `NotImplementedError`; `test_stubs` still asserts `PgVectorStore` raises.

- [ ] **Step 4: Write the failing INTEGRATION tests** `tests/test_integration_pgvector.py` (`pytestmark = pytest.mark.integration`):
```python
def _require_pg():
    pytest.importorskip("psycopg"); pytest.importorskip("pgvector")
    import psycopg
    try:
        with psycopg.connect(_DSN, connect_timeout=3): pass
    except Exception as exc:
        pytest.skip(f"Postgres not reachable: {type(exc).__name__}")

def test_parity_with_in_memory():        # same HashingEmbedder, 4 fixtures → identical ranked doc-id list
    ...  # assert [h.document_id for h in pg.query(q, scope, 5)] == [h.document_id for h in mem...]; scores == pytest.approx
def test_scope_is_a_sql_predicate():     # excluding a top-ranked doc from scope ⇒ no hit from it
    ...
def test_upsert_is_idempotent():         # upsert same chunks twice ⇒ row count == chunk count
    ...
def test_query_equal_to_chunk_scores_near_one():   # cosine orientation guard
    ...
def test_bad_dsn_raises_vector_store_error():       # loud, not silent-empty
    with pytest.raises(VectorStoreError):
        PgVectorStore("postgresql://nope:nope@127.0.0.1:1/none").query([0.0]*256, allowed_document_ids={"x"}, limit=5)
```
  Each test uses an isolated table name (or truncates in a fixture) so runs are independent.

- [ ] **Step 5: Implement `PgVectorStore`** in `vectorstore.py` (replace the stub). Lazy-import `psycopg` + `pgvector.psycopg.register_vector` inside `__init__`; a missing extra → `raise VectorStoreError("pgvector extra not installed: pip install '.[pgvector]'")`. `__init__(dsn)` stores the DSN and runs `_ensure_schema()` (connect with `connect_timeout=_CONNECT_TIMEOUT=10`; `CREATE EXTENSION IF NOT EXISTS vector`; `CREATE TABLE IF NOT EXISTS sair_chunks(chunk_id text primary key, document_id text not null, text text not null, embedding vector(256) not null)` — 256 from `HashingEmbedder.DIM` if exposed, else a pinned constant with a comment). `upsert`: `INSERT … ON CONFLICT (chunk_id) DO UPDATE SET …` (parameterized, `register_vector` per connection). `query`: the §6.2 SQL — `SELECT document_id, text, 1 - (embedding <=> %s) AS score FROM sair_chunks WHERE document_id = ANY(%s) ORDER BY embedding <=> %s LIMIT %s` → `list[ChunkHit]`. Wrap every DB operation so any `psycopg`/connection error re-raises as `VectorStoreError(...) from exc` (no row data in the message). Each method uses a short-lived `with psycopg.connect(...)` (thread-safe by construction).

- [ ] **Step 6: Retire the stub test** — in `tests/test_stubs.py`, drop `PgVectorStore` from the loop so it covers only `OllamaEmbedder` (ruling: mirrors the KEV/Sigma/metrics slices retiring a now-implemented stub's assertion).

- [ ] **Step 7: Run hermetic guards** — `./.venv/bin/pytest tests/test_pgvector_adapter.py tests/test_stubs.py -q` → PASS.

- [ ] **Step 8: Run the integration tests against real pg** — bring up Postgres and install the extra, then run:
```bash
./.venv/bin/pip install -e '.[pgvector]'
docker compose up -d db        # pgvector/pgvector:pg16, loopback
./.venv/bin/pytest -q -m integration tests/test_integration_pgvector.py
```
  Expected: PASS (parity, scope-as-SQL, idempotent, cosine orientation, bad-DSN loud). If Docker is unavailable in this environment, the tests SKIP cleanly — record that in the ledger and rely on the hermetic guards + the final review; the integration tests remain committed and runnable.

- [ ] **Step 9: ROADMAP** — tick the pgvector-schema + upsert-to-pgvector portions of Week 5–6; annotate "Local embeddings via Ollama" and "migrations" as still deferred (do not tick).

- [ ] **Step 10: Run the full hermetic suite** — `./.venv/bin/pytest -q -m "not integration"` → green.

- [ ] **Step 11: Commit** — `feat(retrieval): real PgVectorStore adapter behind the VectorStore seam (Slice 2)`

---

## Final

After Task 4: run `./.venv/bin/pytest -q -m "not integration"` (hermetic gate) and, if pg is available, `-m integration`; then the one fresh **opus-xhigh whole-branch review** (package via `review-package`), re-grade findings by effect, Critical/Important → one TDD fix pass, Minor → ledger; then `superpowers:finishing-a-development-branch` (Option 1: merge to main locally, no push).
