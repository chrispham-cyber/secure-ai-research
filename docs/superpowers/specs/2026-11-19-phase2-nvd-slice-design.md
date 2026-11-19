# Phase 2 Vertical Slice — NVD Evidence-Grounded Retrieval (Design)

**Date:** 2026-11-19 · **Author:** Chris Pham (with Claude) · **Status:** for approval
**Repo:** `secure-ai-research` · **Base:** `main` (Phase-1 scaffold, merged)
**Supersedes nothing.** First real increment of ROADMAP Phase 2 (weeks 5–8).

> **Scope: PUBLIC / synthetic data only.** No network, no CUI/classified. All tests run
> offline against a committed synthetic fixture.

## 1. Intent & why

Phase 1 shipped the architecture, the security primitives, and fail-loud stubs. This slice
turns **one source (NVD)** into a working, cited retrieval path end-to-end —
`ingest → chunk → embed → store → authorize-before-retrieve → cited answer` behind
`GET /research/cve/{cve_id}` — and proves the **security-critical spine**
(authorize-before-retrieval, document-level citation, audit-per-analysis) with **fully
hermetic tests**. It deliberately stops short of real external services and of a generative
model, so the spine is reviewable before anything non-deterministic or network-bound lands.

## 2. Goals

- `GET /research/cve/{cve_id}` returns a **cited answer** assembled from retrieved NVD
  documents (document-level citations: CVE id + `source_url` + the matching passage), or a
  **denial**, and emits **one audit record** per request.
- The whole pipeline is implemented: `nvd.load → chunk → embed → store.upsert`, and at query
  time `authorize → store.query (within authorized scope) → assemble cited answer → audit`.
- `Embedder` and `VectorStore` are **ports** (Protocols) with **deterministic fakes**
  (`HashingEmbedder`, `InMemoryVectorStore`) that exercise the *real* logic (tokenizing,
  cosine ranking, scope filtering) — the entire pipeline is unit-tested with **no network,
  no Postgres, no Ollama**.
- **Authorize-before-retrieve** is demonstrated by a two-caller test: a permitted role gets
  the CVE; an unknown/empty `X-Role` is denied **before** the store is queried.
- **No new runtime dependencies**; fakes are pure Python. ruff/black/mypy clean; TDD.

## 3. Non-goals (this slice)

- **No real adapters.** `OllamaEmbedder` and `PgVectorStore` ship as **fail-loud stubs**
  (raise `NotImplementedError` → next slice). The app and tests run on the fakes.
- **No generative LLM (P5).** The answer is assembled deterministically from retrieved
  passages; `build_report` renders, it does not generate. The local-model draft is a later
  slice.
- **No other sources** (KEV/ATT&CK/Sigma stay stubs), **no MinIO**, **no live NVD fetch**
  (synthetic fixture only — a real fetch script is future), **no chunk-level citation**
  (document-level only), **no `/research/attack` or `/research/search`** (stay 501).

## 4. Anti-goals (failure even if it "works")

- Any answer that is plausible but **uncited**, or any fabricated field.
- Any path by which an **unauthorized/empty role reaches retrieval** (post-filtering results
  is the control already failed — scope must gate the query).
- **Polluting the committed `ResearchDocument` schema** with pipeline-internal fields (text,
  chunks, embeddings). It stays metadata-only.
- A fake that makes tests pass **without exercising real logic** — the fake embedder and
  store must do genuine tokenizing, cosine ranking, and scope filtering.

## 5. Constraints (from the repo & Global Constraints)

- Python 3.12, fully typed, ruff (E/F/I/UP/B, line 100) + black + mypy(`src`) clean.
- TDD (RED→GREEN), fail-loud stubs with roadmap pointers, no fabricated data.
- PUBLIC-only: `classification` pinned PUBLIC; an LLM never sets a class.
- **Tests must not require network/services.** Any real-service test is
  `@pytest.mark.integration` (skipped in CI / `make test`). This slice adds **no** integration
  tests (its real adapters are fail-loud stubs).
- Keep the committed `ResearchDocument` schema unchanged.

## 6. Approaches

- **A — Protocol ports + injected `ResearchService` (CHOSEN).** Define `Embedder` and
  `VectorStore` as Protocols; fakes for unit tests; a `ResearchService` wires the pipeline
  and emits audit; the FastAPI route calls the service. Requires refactoring the three
  Phase-1 module-function stubs (`embed`, `vectorstore.upsert`, `vectorstore.retrieve`) into
  this port shape — **recorded as a ruling** (the stub test's parameter list shrinks
  accordingly).
- **B — Keep module functions, switch impl via config.** Rejected: global state, and the
  two-caller authorization test cannot cleanly inject distinct stores/roles in one test. B
  fights the hermetic-test goal.

Chris picked **A** (2026-11-19).

## 7. The design (decided)

### 7.1 Data carried through the pipeline
`ResearchDocument` stays metadata-only. A new frozen dataclass pairs it with its text:

```python
# ingestion/ingested.py
@dataclass(frozen=True)
class IngestedDocument:
    document: ResearchDocument   # metadata (PUBLIC, sha256 integrity_hash, source_url, …)
    text: str                    # the CVE description text to chunk/embed
```

### 7.2 Ports & value types (`retrieval/ports.py`)
```python
@dataclass(frozen=True)
class ChunkRecord:  # what gets stored
    chunk_id: str; document_id: str; text: str; embedding: list[float]

@dataclass(frozen=True)
class ChunkHit:     # what a query returns
    document_id: str; text: str; score: float

class Embedder(Protocol):
    def embed(self, chunks: list[str]) -> list[list[float]]: ...

class VectorStore(Protocol):
    def upsert(self, entries: list[ChunkRecord]) -> None: ...
    # scope filter is a parameter: the store ranks ONLY within allowed_document_ids
    def query(self, embedding: list[float], *, allowed_document_ids: set[str],
              limit: int) -> list[ChunkHit]: ...
```

### 7.3 Implementations
- **`HashingEmbedder`** (`retrieval/embeddings.py`): deterministic bag-of-words hashed into a
  fixed dimension (default 256), L2-normalized → cosine reflects token overlap. Pure Python.
- **`OllamaEmbedder`** (same file): **fail-loud stub — raises `NotImplementedError`
  (message contains "ROADMAP Phase") in `__init__`**, so no path holds a half-live adapter.
- **`InMemoryVectorStore`** (`retrieval/vectorstore.py`): holds `ChunkRecord`s; `query`
  cosine-ranks **only** entries whose `document_id ∈ allowed_document_ids`, returns top-`limit`
  `ChunkHit`s. Pure Python.
- **`PgVectorStore`** (same file): **fail-loud stub — raises in `__init__`** (as above).
- **`chunking.chunk(text, *, size=800, overlap=150) -> list[str]`**: deterministic
  overlapping windows on whitespace boundaries.
- **`authz.authorize(role, doc) -> bool`**: **allowlist = `{research_analyst,
  senior_analyst}`** (the two roles `roles.md` grants corpus retrieval), matched exactly after
  `strip()`. Every other value — `security_auditor`, `model_admin`, `data_steward`,
  `administrator`, unknown, empty — returns `False` (**deny-by-default**). In PUBLIC-only this
  is the demonstrable denial; richer ABAC (source/class scope) arrives with real
  classifications (Phase 5).
- **`ingestion/nvd.load(raw: bytes) -> list[IngestedDocument]`**: parse NVD 2.0 JSON
  (`vulnerabilities[].cve`): `id`, English `descriptions[].value` → `text`, `published` →
  `created_at` (date), `source_url` = `https://nvd.nist.gov/vuln/detail/{id}`,
  `integrity_hash` = `sha256:` of the per-CVE **canonical JSON**
  (`json.dumps(cve, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()`),
  `document_type=VULNERABILITY`, `classification=PUBLIC`, `source="NVD"`. **Fail-loud**: bad
  JSON, a record with no English description, a non-date `published`, or a **duplicate id**
  raises a clear `ValueError` naming the offending id — never a silent skip.

### 7.4 Orchestration (`research_service.py`)
```python
class Outcome(StrEnum): OK = "OK"; DENIED = "DENIED"; NOT_FOUND = "NOT_FOUND"

class ResearchService:
    def __init__(self, embedder: Embedder, store: VectorStore,
                 authorize: Callable[[str, ResearchDocument], bool],
                 audit_path: Path, limit: int = 5): ...
    def index(self, docs: list[IngestedDocument]) -> None:
        # per doc: chunk(text) → embedder.embed(chunks) → store.upsert(ChunkRecords);
        # also register document_id -> ResearchDocument for authorization.
    def research_cve(self, cve_id: str, *, role: str) -> ResearchResult:
        # 0. cve_id is already format-validated by the router (see §7.5).
        # 1. allowed = {id for id,doc in registry if authorize(role, doc)}   ← BEFORE retrieve
        # 2. if not authorize(role, this CVE's doc):  emit DENIED audit (no corpus metadata),
        #       return ResearchResult(outcome=DENIED)                        ← scope never queried
        # 3. if cve_id not in registry: emit NOT_FOUND audit, return ResearchResult(NOT_FOUND)
        # 4. scope = allowed ∩ {cve_id}   (this slice grounds a CVE answer in its OWN document;
        #       cross-document semantic search is /research/search, a later slice)
        # 5. hits = store.query(embedder.embed([query_text])[0], allowed_document_ids=scope, limit)
        # 6. model_output = "\n".join(f"{hit.text} [{hit.document_id}]" for hit);  a claim line
        #       with no [id] token, or an id not in retrieved_doc_ids, is dropped by build_report.
        # 7. emit OK audit ResearchRecord, answer = build_report(record)
        # 8. return ResearchResult(OK, answer, citations=[{document_id, source_url, passage}], research_id)
```
**`ResearchResult`** (frozen): `outcome: Outcome`, `answer: str`, `citations: list[Citation]`,
`research_id: str`. **Audit record** (`audit.record.emit` to the injected `audit_path`):
`analyst_id` = the role (or `"anonymous"` if empty), `objective` =
`f"Correlate {cve_id} against public sources"`, `data_source_ids=["NVD"]`,
`model_id="retrieval-only"`, `model_version=""`, `prompt_template_version=""`. **A DENIED or
NOT_FOUND record carries no corpus metadata** — empty `retrieved_doc_ids`, `document_hashes`,
and a `conclusion` naming only the outcome (no document ids/hashes leak to an unauthorized
trail, per the audit README). **`build_report(record)`** keeps its Phase-1 signature: it renders
`objective` + the kept (cited) claim lines from `model_output` + a `Sources:` list of
`retrieved_doc_ids`; it drops any uncited claim line. `source_url` lives only in the structured
`citations` (the record has no url field), so the rendered report cites by document id.

### 7.5 API wiring (`api/routers/research.py`, `api/deps.py`)
- **Role** comes from the `X-Role` dev header (Phase-1 stub; absent → `""`). **`cve_id` is
  format-validated at the route** via `Path(pattern=r"^CVE-\d{4}-\d{4,}$")` → a malformed id is
  a **422** before any audit/retrieval (kills log-injection / unbounded-input via the id).
- The route depends on **`get_service()`** (FastAPI `Depends`), so it never relies on
  startup/lifespan events — which matters because `tests/test_api.py` uses a module-level
  `TestClient(app)` that runs no lifespan. The default `get_service` lazily builds and
  **`@lru_cache`s** one fake-backed `ResearchService`, indexing the packaged synthetic fixture
  on first use. Tests **override `get_service`** (`app.dependency_overrides`) with a service on
  a `tmp_path` audit log and a small indexed corpus — so API tests never write into the repo.
- **Status map** (router translates `ResearchResult.outcome`):

  | Case | Status | Body |
  |---|---|---|
  | permitted role, CVE present | **200** | `{answer, citations, research_id}` |
  | role not in allowlist / empty | **403** | `{detail, research_id}` — denied before retrieve |
  | permitted role, CVE absent | **404** | `{detail, research_id}` |
  | malformed `cve_id` | **422** | FastAPI validation error (no audit) |

  `/research/attack` and `/research/search` stay **501**.

### 7.6 Synthetic fixture (packaged)
`src/secure_ai_research/ingestion/samples/nvd_sample.json` — **packaged** data (via
`importlib.resources`, with `pyproject` package-data for `samples/*.json`; `samples/` not
`data/`, because `.gitignore` ignores any `data/` dir), not under `tests/`, so the
installed app and the tests read the same corpus. Real NVD 2.0 shape
(`{"vulnerabilities":[{"cve":{...}}]}`), 2–3 **clearly synthetic** records (`CVE-2099-0001` …)
with plain-English descriptions written to make retrieval demonstrable.

## 8. Testing strategy
Unit (hermetic): `nvd.load` field mapping + sha256 **and fail-loud raises** (bad JSON, no-EN
description, duplicate id); `chunk` windows/overlap; `HashingEmbedder` determinism + cosine;
`InMemoryVectorStore` ranking + `allowed_document_ids` filter; `authorize` allowlist/deny
(`research_analyst` yes, `security_auditor`/unknown/`""` no); `ResearchService`
permitted→cited (CVE present, OK audit emitted) vs empty-role→DENIED (**store never queried**,
denied audit carries **no** doc ids/hashes) vs permitted+absent→NOT_FOUND; `build_report` cited
render + **uncited claim line dropped**; API `GET /research/cve/{id}` → 200 cited (`X-Role:
research_analyst`), 403 (no/unknown role), 404 (`CVE-2099-9999`), 422 (`not-a-cve`). The two
adapter stubs: constructing `OllamaEmbedder`/`PgVectorStore` raises with "ROADMAP Phase". Update
`test_stubs.py` to drop the now-implemented callables (nvd.load, chunk, embed, vectorstore.*,
authz.authorize) — kev/attack/sigma, metrics.score, and the agent functions remain stubs.

## 9. What's left to the builder
Chunk `size`/`overlap` defaults, `HashingEmbedder` dimension, top-`k` (suggest 5), the exact
cited-answer string format, `chunk_id`/`research_id` scheme (deterministic or uuid), and the
synthetic fixture's 2–3 CVE contents (clearly synthetic ids, e.g. `CVE-2099-0001`). Idiomatic
within the signatures above.

## 10. Deviations recorded as rulings (at build time)
- Refactor the three module-function retrieval stubs into Protocol ports (Approach A).
- `nvd.load` returns `list[IngestedDocument]` (was `list[ResearchDocument]`) — the pipeline
  needs source text and the committed schema stays metadata-only.
- `vectorstore.query(..., allowed_document_ids=...)` replaces the Phase-1
  `retrieve(query, *, role)` — authorization is computed in the service and passed as scope, so
  the store ranks only within authorized documents (authorize-before-retrieve, by construction).
- `/research/cve/{id}` grounds the answer in the **requested CVE's own document** (scope =
  `allowed ∩ {cve_id}`), returns **404** when that CVE is absent, and validates `cve_id` format
  → **422** — all three resolve the builder's "wrong-CVE / unknown / log-injection" questions
  toward the no-wrong-or-uncited-answer anti-goal. Cross-document semantic search is a later
  `/research/search` slice.
- Permitted-role allowlist = `{research_analyst, senior_analyst}` per `roles.md`; every other
  role (incl. `data_steward`, `administrator`) is denied this slice — richer scope later.
