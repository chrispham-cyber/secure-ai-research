# Phase 5 Slice 2 — pgvector VectorStore (Design)

**Status:** proposed (awaiting Chris's approval — the one gate before build)
**Date:** 2026-11-19
**Repo:** `/Users/fox/Chris/CyberBase/secure-ai-research` (local git, no remote, main@6a7eb74)
**Prior art:** Slice 1a (real Ollama `Generator` behind the seam) sets the exact pattern this slice mirrors for the `VectorStore` seam.

---

## 1. Intent & why

The platform has shipped on a deterministic, dependency-free `InMemoryVectorStore` behind the `VectorStore` Protocol since Phase 2. Slice 2 delivers the **real Postgres/pgvector adapter** (`PgVectorStore`) that the stub has promised — the first real-infra backing for retrieval — **without weakening the default offline/hermetic/no-dep posture**. This is the ROADMAP Phase-2 Week 5–6 "pgvector schema + upsert chunks+embeddings to pgvector" deliverable, pulled forward into the Phase-5 build-then-harden batch.

The point of the slice is to **de-risk the Protocol and the SQL**: prove a real vector database can sit behind `VectorStore` and return the *same ranked results* as the in-memory store, with authorization enforced **as a SQL predicate** (not a post-filter), and with any store failure **failing closed** to the project's one-audit-record invariant — all while `pytest` (default) stays hermetic and the Phase-4 `1.0` gate is untouched.

**Why now:** it is the next slice in the agreed 8-slice Phase-5 batch, and the infra already exists — `docker-compose.yml` ships `db: pgvector/pgvector:pg16` (loopback-bound, healthchecked) and `config.db_url` already carries the DSN. Nothing new needs provisioning to test it.

---

## 2. Goals / Non-goals / Anti-goals

### Goals
- A real `PgVectorStore` implementing the existing `VectorStore` Protocol (`upsert`, `query`), replacing the fail-loud stub.
- **Ranking parity** with `InMemoryVectorStore` over the committed corpus using the **same deterministic `HashingEmbedder`** — a verifiable equality of the ranked document-id list, not a fuzzy "seems similar."
- Authorization enforced **inside the SQL** (`WHERE document_id = ANY(...)`), preserving authz-by-construction.
- Opt-in via `SAIR_VECTOR_STORE=pgvector`; **default `memory` is byte-identical** to today (every hermetic test + the Phase-4 regression gate unchanged).
- **Fail-closed:** any store failure at request time → `Outcome.FETCH_ERROR` + **exactly one audit record** (type-only, no payload leak), surfaced as **503** on every route over the store.
- Real adapter exercised behind `-m integration` (skips cleanly when Postgres is unreachable or the extra is not installed); `psycopg`/`pgvector` are an **optional extra**, never imported by the default suite.

### Non-goals (explicitly out of this slice)
- **Real embeddings** (`OllamaEmbedder`). The embedder stays the deterministic `HashingEmbedder`; `OllamaEmbedder` remains a fail-loud stub for a later slice. (This is what makes parity a hard equality.)
- **Migrations / schema-version framework.** A1 uses `CREATE TABLE IF NOT EXISTS` + idempotent upsert; a real migration tool (alembic) is deferred.
- **Approximate-nearest-neighbour index (ivfflat/hnsw).** Exact sequential scan only, so parity is exact; an ANN index trades exactness for speed and is deferred until corpus scale needs it.
- **MinIO / object store** (separate Slice 3), **OIDC** (Slice 4), **true cross-restart persistence as a contract** (A2 — see §5).
- Connection pooling. A short-lived connection per operation (thread-safe by construction) is enough at this scale; a pool is a documented future optimization.

### Anti-goals (a failure even if it "works")
- `pytest` (default) requiring Postgres, importing `psycopg`, or going non-hermetic.
- A silent fallback to `InMemoryVectorStore` when pgvector is misconfigured or down (a configured-but-unreachable store must fail **loud**, never pretend).
- A store failure that produces an **unhandled 500 with no audit record**, or that a route **masks as a 404 / empty-200**.
- Authorization applied as a post-query filter (an unauthorized document must never be *ranked*, only never *returned*).
- Any change to the default (`memory`) runtime behavior or output bytes.

---

## 3. Constraints (inherited, verbatim where pinned)

- Python ≥ 3.12; `.venv/bin/python`. TDD throughout. Attribution footer on commits.
- **PUBLIC / synthetic data only.** Dev credentials in `docker-compose.yml`/`config.py` are well-known local-dev placeholders; never commit real secrets or a `.env`.
- **No new *default* runtime dependency.** `psycopg`/`pgvector` enter only as `[project.optional-dependencies].pgvector`, lazily imported inside the adapter.
- Default run is hermetic: `addopts = ["-m", "not integration"]`. The `integration` marker already means "requires live services (Postgres/MinIO/Ollama) or network."
- One audit record per request, on every path (the invariant guarded across `_research`, `search`, `ask`, the fetcher, and the generator).
- Local only — **no push without Chris's go.**

---

## 4. Current state (what the change touches)

- `retrieval/ports.py` — `VectorStore` Protocol (`upsert(entries) -> None`, `query(embedding, *, allowed_document_ids, limit) -> list[ChunkHit]`), `ChunkRecord`, `ChunkHit`. *(No `VectorStoreError` yet — `generation/ports.py` has the sibling `GeneratorError`.)*
- `retrieval/vectorstore.py` — `InMemoryVectorStore` (cosine in-scope → sort desc → `[:limit]`) + the `PgVectorStore` fail-loud stub.
- `research_service.py` — three request paths call `self._store.query`, **none wrapped** for store failure:
  - `_research` (id-routes) line ~209 — direct `store.query`.
  - `_retrieve_corpus` line ~323 — `store.query`, shared by `search` + `ask`.
- `api/routers/research.py` — `cve` and `ask` already map `FETCH_ERROR→503`; **`attack` and `search` do not** (they fall through to 404 / 200).
- `api/deps.py` — constructs `InMemoryVectorStore()` **inline** (the generator already uses `make_generator(settings)`).
- `config.py` — `db_url` default `postgresql://sair:sair@localhost:5432/sair` (matches compose). No `vector_store` setting yet.
- `tests/test_stubs.py` — asserts `PgVectorStore()` raises `NotImplementedError` (retire this half; `OllamaEmbedder` stays).
- `pyproject.toml` — `[project.optional-dependencies]` exists (line ~22); `integration` marker + hermetic `addopts` configured.

---

## 5. Approaches considered

**A1 — pgvector as the query engine, re-index on startup (CHOSEN).**
`deps` indexes the 4 committed fixtures every boot; `upsert` writes vectors with `ON CONFLICT (chunk_id) DO UPDATE` (idempotent) into a `CREATE TABLE IF NOT EXISTS` table. Postgres is the ANN query engine; the ingest flow is unchanged from today ("index fixtures at startup"). Data survives in the compose volume, but the slice **does not depend on** that — a wiped volume just re-indexes. No migration framework.
*Trade:* smallest change that proves the Protocol + the SQL + the fail-closed wiring; lowest risk. Doesn't exercise a persistence contract.

**A2 — true persistence (rejected for this slice).**
Vectors survive restart as a contract; boot skips re-indexing when already populated; implies a schema-version check, a migration story, and drift handling.
*Rejected because:* the corpus is 4 deterministic fixtures that rebuild identically, so a persistence contract buys little today and costs a migration framework now. Revisit when dynamic ingestion (not fixtures) exists. (Chris chose A1.)

**B — pgvector as the default with a hermetic fallback (rejected).**
Makes bare `pytest` need Postgres (or a fragile auto-fallback) and introduces a default DB dependency — against the posture every slice has held. Rejected outright.

---

## 6. Decided design (the how)

### 6.1 Component map

| File | Change |
|---|---|
| `retrieval/ports.py` | **Add** `class VectorStoreError(Exception)` (seam error type, sibling of `GeneratorError`). |
| `retrieval/vectorstore.py` | **Replace** the `PgVectorStore` stub with the real adapter (lazy `psycopg`/`pgvector` import; connect, ensure schema, upsert, query; raise `VectorStoreError` on any DB fault). `InMemoryVectorStore` untouched. |
| `retrieval/factory.py` | **New** `make_vector_store(settings) -> VectorStore` (mirrors `generation/factory.py`): `pgvector` → `PgVectorStore(settings.db_url)`, else `InMemoryVectorStore()`. |
| `config.py` | **Add** `vector_store: Literal["memory", "pgvector"] = "memory"`. |
| `api/deps.py` | **Swap** inline `InMemoryVectorStore()` → `make_vector_store(settings)`. Nothing else changes. |
| `research_service.py` | **Wrap** the three store-query sites so a store fault → `FETCH_ERROR` + one `_emit_terminal`, type-only (mirrors the generator/fetcher two-arm pattern). |
| `api/routers/research.py` | **Add** `FETCH_ERROR→503` to the `attack` and `search` routes; update their docstrings. `cve`/`ask` unchanged. |
| `pyproject.toml` | **Add** `[project.optional-dependencies] pgvector = ["psycopg[binary]>=3.2", "pgvector>=0.3"]`. |
| `tests/test_stubs.py` | **Retire** the `PgVectorStore` entry (ruling; `OllamaEmbedder` stays). |
| `ROADMAP.md` | **Tick** the pgvector-schema + upsert-to-pgvector portions of Week 5–6; annotate Ollama-embeddings + migrations as still deferred. |
| `tests/test_pgvector_factory.py` (hermetic) · `tests/test_store_failclosed.py` (hermetic) · `tests/test_integration_pgvector.py` (`-m integration`) | **New** tests (see §7). |

### 6.2 `PgVectorStore` adapter

- **Lazy import:** `import psycopg` and `from pgvector.psycopg import register_vector` happen **inside `__init__`**, so the default suite never imports them. If the extra is absent, raise a clear `VectorStoreError` naming the missing extra (`pip install '.[pgvector]'`) — never a bare `ImportError` surfacing from a query.
- **Connection model:** a short-lived connection **per operation** — `with psycopg.connect(self._dsn, connect_timeout=_CONNECT_TIMEOUT) as conn:` — thread-safe by construction (no shared mutable connection under the threaded server). `_CONNECT_TIMEOUT` is a module constant (10s) for now.
- **Schema (ensured in `__init__`, fails loud at startup if pg is down — the desired boot-time fail-closed):**
  ```sql
  CREATE EXTENSION IF NOT EXISTS vector;
  CREATE TABLE IF NOT EXISTS sair_chunks (
      chunk_id    text PRIMARY KEY,
      document_id text NOT NULL,
      text        text NOT NULL,
      embedding   vector(256) NOT NULL   -- 256 = HashingEmbedder.DIM (pinned via a constant)
  );
  ```
  **No ANN index** — exact sequential scan, so ranking is exact and parity holds.
- **`upsert(entries)`:** one `executemany`/`INSERT ... ON CONFLICT (chunk_id) DO UPDATE SET document_id=…, text=…, embedding=…`. Idempotent: re-indexing the same fixtures on the next boot updates in place, never duplicates.
- **`query(embedding, *, allowed_document_ids, limit)`:**
  ```sql
  SELECT document_id, text, 1 - (embedding <=> %(q)s) AS score
  FROM sair_chunks
  WHERE document_id = ANY(%(scope)s)
  ORDER BY embedding <=> %(q)s
  LIMIT %(limit)s;
  ```
  - `<=>` is pgvector **cosine distance**; `score = 1 - distance` recovers **cosine similarity** to match `ChunkHit.score` and the service-side `score > 0` floor.
  - `ORDER BY distance ASC` = similarity DESC = the in-memory `sort(score, reverse=True)`.
  - **Scope is the `WHERE` predicate** — authorization gates retrieval *in the query*, never as a post-filter. An empty scope is never passed (the service only calls `query` with a non-empty scope).
  - All values are **parameterized** (no string interpolation into SQL).
  - Returns `list[ChunkHit]` exactly as the Protocol requires. The service applies the `score > 0` floor and dedup unchanged.
- **Failure:** any `psycopg`/connection/query error is caught and re-raised as `VectorStoreError(...) from exc` — message carries no row data.

### 6.3 `VectorStoreError` + fail-closed wiring

- New typed `VectorStoreError(Exception)` in `retrieval/ports.py`; `research_service` imports it for the typed arm.
- **Three request entrypoints** wrap their store access, each emitting **exactly one** terminal record and returning `FETCH_ERROR`, recording only `type(exc).__name__`:
  - `_research`: wrap the `store.query(...)` call (id-routes).
  - `search`: wrap the `r = self._retrieve_corpus(...)` call.
  - `ask`: wrap the `r = self._retrieve_corpus(...)` call (before the empty-retrieval / synthesis branches).
  Pattern mirrors the generator path: `except VectorStoreError` (typed) then `except Exception` (defense-in-depth — the store is injected via Protocol/factory), both → `fetch_error: retrieval failed (<Type>)`.
  A DENIED role never reaches `store.query` (`_retrieve_corpus` returns before querying on empty `allowed`; `_research` returns on empty `allowed`), so DENIED semantics are unchanged.
- **Startup** (`index()` / `upsert`, `__init__`): errors **propagate** = loud boot failure when `pgvector` is selected but unreachable. That is the intended fail-closed-at-startup behavior; no special handling.

### 6.4 Router: surface the failure as 503 everywhere over the store

Once the shared store can fail at request time, every route over it must surface it, not mask it:
- `attack` route — **add** `if res.outcome is Outcome.FETCH_ERROR: 503` before the 404; update the docstring (it currently says "no 503 path here").
- `search` route — **add** `if res.outcome is Outcome.FETCH_ERROR: 503` before the 200; update the docstring ("no 404/503" → "no 404; 503 only when the store is unavailable").
- `cve` / `ask` — already map `FETCH_ERROR→503`; unchanged.

### 6.5 Factory, config, deps

- `config.Settings` gains `vector_store: Literal["memory", "pgvector"] = "memory"` (env `SAIR_VECTOR_STORE`).
- `retrieval/factory.make_vector_store(settings)` returns `PgVectorStore(settings.db_url)` for `"pgvector"`, else `InMemoryVectorStore()`.
- `deps.get_service` calls `make_vector_store(settings)` in place of the inline `InMemoryVectorStore()`. Default `"memory"` ⇒ identical wiring and bytes.

### 6.6 Dependency as an optional extra

`pyproject.toml`:
```toml
[project.optional-dependencies]
pgvector = ["psycopg[binary]>=3.2", "pgvector>=0.3"]
```
Installed with `pip install -e '.[pgvector]'`. The default install and the default runtime never pull it. (First real DB runtime dep for the project — opt-in only; this is the one posture-relevant addition, flagged for Chris.)

### 6.7 Parity semantics (honest)

`InMemoryVectorStore` computes cosine in Python `float64`; pgvector computes in C. Scores can differ in the last ulps, so parity is asserted on **the ranked document-id list** (membership + order) and on **scores within a tolerance** (`pytest.approx`), *not* exact float equality. For the deterministic `HashingEmbedder` over the 4 fixtures there are no near-ties expected, but the test is written to the honest claim ("same ranking, scores ≈ equal"), which is the meaningful property and robust to float noise.

---

## 7. Testing strategy

**Hermetic (default suite — no Postgres, no `psycopg` import):**
1. `make_vector_store` returns `InMemoryVectorStore` by default, and `SAIR_VECTOR_STORE=pgvector` parses to `settings.vector_store == "pgvector"` (factory branch chosen; the pgvector *construction* is integration-only since it connects).
2. **Fail-closed wiring** via a `_RaisingStore` fake (implements `VectorStore`, `.query` raises `VectorStoreError`, then a second fake raising a plain `RuntimeError` for the defense-in-depth arm): assert `search`, `ask`, and an id-route (`research_cve`) each return `Outcome.FETCH_ERROR` and write **exactly one** audit record (count lines in a temp audit log), with no payload in the record. This proves the invariant **without Postgres** — the direct analogue of Slice 1a's generator-fail-closed hermetic tests.
3. `VectorStoreError` is importable from `retrieval.ports`.
4. Router: with a service stub returning `FETCH_ERROR`, `attack` and `search` now return **503** (TestClient).

**Integration (`-m integration`, excluded by default/CI; skips cleanly):**
`_require_pg()` — `pytest.importorskip("psycopg")`, `pytest.importorskip("pgvector")`, then attempt `psycopg.connect(dsn, connect_timeout=3)` and `pytest.skip(...)` on failure (mirrors `_require_ollama()`); each test uses a unique table or truncates, so runs are independent.
1. **Parity:** index the 4 fixtures into both stores with the same `HashingEmbedder`; for a set of probe queries assert `[h.document_id for h in pg.query(...)] == [h.document_id for h in mem.query(...)]` and scores `== pytest.approx(...)`.
2. **Scope-as-SQL:** `query` with `allowed_document_ids` excluding an otherwise top-ranked document returns **no hit from that document** (authz-by-construction in the `WHERE`).
3. **Idempotent upsert:** upsert the same chunks twice → `SELECT count(*)` equals the chunk count (no duplication; `ON CONFLICT DO UPDATE` verified).
4. **Cosine orientation:** the top hit for a query equal to a stored chunk's text is that chunk, `score ≈ 1.0` (guards against the distance/similarity sign error).
5. **Fail-closed, real:** a `PgVectorStore` built on a bad DSN raises `VectorStoreError` (loud), not a silent empty result.

**Test command:** `./.venv/bin/pytest -q -m "not integration"` (hermetic); `./.venv/bin/pytest -q -m integration` (real pg, after `pip install -e '.[pgvector]'` + `docker compose up -d db`).

---

## 8. Security / threat notes

- **Authz-by-construction preserved:** scope is a SQL `WHERE` predicate, so an unauthorized document is never ranked, never returned (not a post-filter). This is the same property `InMemoryVectorStore` enforces via the in-scope comprehension.
- **One-audit-record invariant extended to the store:** a store outage is now a first-class `FETCH_ERROR` with exactly one record (type-only), on every route — closing the "unhandled 500 / masked 404 / empty-200" gaps the router has today.
- **No new default attack surface:** the DB dep is opt-in; the default build has no `psycopg`, no network, no DB.
- **SQL injection:** all queries parameterized; ids and vectors are bound parameters, never interpolated.
- **Dev-cred posture unchanged:** `sair:sair@localhost` is a documented local-dev placeholder for synthetic data on a loopback-bound port; real deployments override via env and never rely on the fallback (already stated in compose/config).
- **X-Role** remains the documented Phase-5 OIDC-replacement stub (Slice 4) — out of scope here.

---

## 9. ROADMAP accounting (honest)

- Week 5 "pgvector **schema**": ✅ (the `sair_chunks` `vector(256)` table via `CREATE TABLE IF NOT EXISTS`). "**+ migrations**": ❌ still deferred (A1, no migration framework) — annotate, don't tick.
- Week 6 "**upsert chunks+embeddings to pgvector**": ✅ (the adapter's idempotent upsert, wired via `deps` opt-in). "**Local embeddings via Ollama**": ❌ still deferred (`OllamaEmbedder` stub stays; this slice keeps `HashingEmbedder`) — annotate, don't tick.

---

## 10. Review Focus (most likely to bite; each gets a test in its owning task)

1. **Store failure mid-request on every route** — pg drops after boot; must be **503 + one audit record** on `cve`/`attack`/`search`/`ask`, never an unhandled 500 nor a masked 404/empty-200. *(Hermetic `_RaisingStore` across all entrypoints + router 503 tests.)*
2. **Cosine distance vs similarity sign error** — forgetting `1 - (… <=> …)` inverts ranking and breaks the `score > 0` floor. *(Integration parity + "query == chunk ⇒ score ≈ 1.0".)*
3. **Scope not enforced in SQL** — scope applied post-query, or omitted, lets an unauthorized doc rank in. *(Integration scope-as-SQL test.)*
4. **Non-idempotent re-index** — missing `ON CONFLICT` duplicates chunks every boot, inflating counts/ranks. *(Integration upsert-twice row-count test.)*
5. **Extra selected but not installed / default suite imports psycopg** — must fail loud with a clear remediation message, and the hermetic suite must never import `psycopg`. *(Lazy import + clear `VectorStoreError`; `importorskip` guards integration.)*

---

## 11. What's left to the builder

- Exact SQL dialect details (named vs positional params, `executemany` vs `execute` with `ANY`), and whether `register_vector` is per-connection (yes, per the pgvector/psycopg3 adapter) — settle idiomatically.
- The precise float tolerance for the parity assertion.
- The exact arm count / comment wording of the fail-closed `try/except` blocks (mirror the generator path's two-arm style for house consistency).
- Where `HashingEmbedder.DIM` is read from (class constant vs a pinned literal with a comment) — single-source it if the attribute exists.
- Table isolation strategy for integration tests (unique table name per test, or `TRUNCATE` in a fixture).

---

*Approaches chosen with Chris: A1 (query-engine, re-index on boot). Dependency-as-optional-extra, fail-closed-to-503-everywhere, and exact-NN-no-index are the author's calls, flagged above. On approval: `superpowers:writing-plans` → `superpowers:executing-plans` (continuous; gates kept: TDD + opus-xhigh whole-branch review + merge-to-main-local; no push).*
