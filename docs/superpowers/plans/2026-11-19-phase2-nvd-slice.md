# Phase 2 NVD Evidence-Grounded Retrieval — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the NVD source into a working, cited retrieval path — `GET /research/cve/{cve_id}` answers from retrieved synthetic NVD documents or denies, with authorize-before-retrieve and one audit record per request, all hermetically testable.

**Architecture:** Protocol ports (`Embedder`, `VectorStore`) with deterministic pure-Python fakes (`HashingEmbedder`, `InMemoryVectorStore`); an injected `ResearchService` orchestrates ingest→chunk→embed→store and, at query time, authorize→scoped-retrieve→assemble-cited-answer→audit. Real adapters (`OllamaEmbedder`, `PgVectorStore`) ship as fail-loud stubs. No LLM: the answer is assembled deterministically from passages. Document-level citations.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, pytest. Stdlib only for new logic (`hashlib`, `json`, `re`, `uuid`, `datetime`, `importlib.resources`). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-19-phase2-nvd-slice-design.md`

## Global Constraints

- Python 3.12; every task ends ruff-clean (`select = E,F,I,UP,B`, line 100), black-clean (100), and mypy-clean (`files=["src"]`).
- TDD (Iron Law): no production code without a failing test watched fail first. Each task's final gate is the **whole** suite green: `pytest` from the repo root.
- **No new runtime dependencies.** New logic uses the stdlib only.
- Posture **PUBLIC / synthetic only**: `classification` stays pinned PUBLIC; the fixture uses clearly synthetic ids (`CVE-2099-xxxx`). The committed `ResearchDocument` schema (`ingestion/schema.py`) is **unchanged**.
- Tests are **hermetic**: no network, no Postgres/Ollama/MinIO. This slice adds **no** `@pytest.mark.integration` tests.
- The audit log is append-only JSON Lines, **one line per record** (`ResearchRecord.model_dump_json()`, never indented). API/service tests write audit to a `tmp_path`, never into the repo.
- Role allowlist for retrieval = `{research_analyst, senior_analyst}` (per `infrastructure/identity/roles.md`); everything else is denied (deny-by-default).
- No fabricated or plausible-but-uncited output: an uncited claim is dropped, never shown as fact.
- Commit messages end with the attribution footer:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU
  ```

## Review Focus

1. **Integrity-hash stability** — `nvd.load` must hash a *canonical* serialization; the same CVE with its JSON keys in a different order must produce an identical `integrity_hash`, or provenance breaks on re-ingest. *(Test added in Task 1.)*
2. **Zero-vector embeddings** — a chunk or query with no alphanumeric tokens yields a zero vector; cosine must not divide by zero / return NaN. Embedding stays finite; a zero-norm query ranks nothing and does not crash. *(Tests added in Tasks 3 and 4.)*
3. **Multi-line answer round-trips as one JSONL line** — the assembled answer spans several lines; `emit` then `read_records` must return exactly one record (guards the Phase-1 audit-corruption class). *(Test added in Task 7.)*
4. **Denied / not-found audit records carry no corpus metadata** — `retrieved_doc_ids` and `document_hashes` are empty and the conclusion names only the outcome, so a document id/hash never leaks into an unauthorized caller's trail. *(Tests added in Task 7.)*
5. **Well-formed-but-absent vs malformed `cve_id`** — an absent CVE (valid format) returns 404 **and still emits an audit record** (a probing caller is logged); a malformed id is rejected 422 **before** any audit/retrieval. *(Tests added in Task 8.)*

---

### Task 1: NVD ingestion → `IngestedDocument` + synthetic fixture

**Files:**
- Create: `src/secure_ai_research/ingestion/ingested.py`
- Modify: `src/secure_ai_research/ingestion/nvd.py`
- Create: `src/secure_ai_research/ingestion/samples/nvd_sample.json`
- Modify: `pyproject.toml` (package-data)
- Test: `tests/test_nvd.py`
- Modify: `tests/test_stubs.py` (drop the now-real `nvd.load` row)

**Interfaces:**
- Produces: `IngestedDocument` (frozen dataclass: `document: ResearchDocument`, `text: str`); `nvd.load(raw: bytes) -> list[IngestedDocument]`; the packaged fixture readable via `importlib.resources.files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json")`.

- [ ] **Step 1: Commit the synthetic fixture** `src/secure_ai_research/ingestion/samples/nvd_sample.json` (exact content — NVD 2.0 shape, clearly synthetic, descriptions contain the CVE id so retrieval is demonstrable):

```json
{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2099-0001",
        "published": "2099-01-15T00:00:00.000",
        "descriptions": [
          {"lang": "en", "value": "CVE-2099-0001 is a synthetic SQL injection in the example login form that lets an unauthenticated attacker read arbitrary rows from the accounts database. This record is fictional test data."},
          {"lang": "es", "value": "Dato de prueba sintetico."}
        ],
        "references": [{"url": "https://example.test/advisory/0001"}]
      }
    },
    {
      "cve": {
        "id": "CVE-2099-0002",
        "published": "2099-03-22T00:00:00.000",
        "descriptions": [
          {"lang": "en", "value": "CVE-2099-0002 is a synthetic path traversal in the example file-export endpoint allowing a low-privileged user to read files outside the intended directory. This record is fictional test data."}
        ],
        "references": []
      }
    }
  ]
}
```

- [ ] **Step 2: Add package-data to `pyproject.toml`** so the fixture ships in the wheel:

```toml
[tool.setuptools.package-data]
"secure_ai_research.ingestion" = ["samples/*.json"]
```

- [ ] **Step 3: Write the failing tests** in `tests/test_nvd.py`:
  - `test_load_parses_fixture_into_documents`: read the packaged fixture bytes via `importlib.resources`; `docs = nvd.load(raw)`; assert `len(docs) == 2`; the first is an `IngestedDocument` whose `document.document_id == "CVE-2099-0001"`, `document.source == "NVD"`, `document.document_type == DocumentType.VULNERABILITY`, `document.classification == Classification.PUBLIC`, `str(document.source_url) == "https://nvd.nist.gov/vuln/detail/CVE-2099-0001"`, `document.created_at == date(2099, 1, 15)`, `document.integrity_hash` matches `^sha256:[0-9a-f]{64}$`, and `text` is the English description (contains `"SQL injection"`).
  - `test_load_integrity_hash_is_canonical` *(Review Focus 1)*: build two one-CVE feeds with the same `cve` object but its keys in different insertion order; assert `nvd.load(a)[0].document.integrity_hash == nvd.load(b)[0].document.integrity_hash`.
  - `test_load_rejects_bad_json`: `nvd.load(b"not json")` raises `ValueError`.
  - `test_load_rejects_missing_english_description`: a CVE whose `descriptions` has no `lang == "en"` entry → `ValueError` naming the id.
  - `test_load_rejects_duplicate_ids`: a feed with two CVEs sharing an id → `ValueError` naming the id.

- [ ] **Step 4: Run the tests, verify they fail** — `pytest tests/test_nvd.py -v`; Expected: FAIL (`nvd.load` still raises `NotImplementedError` / `IngestedDocument` missing).

- [ ] **Step 5: Implement `IngestedDocument`** in `ingestion/ingested.py` as a `@dataclass(frozen=True)` with `document: ResearchDocument` and `text: str`.

- [ ] **Step 6: Implement `nvd.load(raw: bytes) -> list[IngestedDocument]`** in `ingestion/nvd.py`. For each `vulnerabilities[].cve`: take `id`; the English description (`descriptions` entry with `lang == "en"`) as `text` (raise `ValueError` if none); `created_at = date.fromisoformat(published[:10])`; `source_url = f"https://nvd.nist.gov/vuln/detail/{id}"`; `source = "NVD"`; `document_type = VULNERABILITY`; `classification = PUBLIC`. Compute `integrity_hash`:

```python
canonical = json.dumps(cve, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
integrity_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
```
  Raise `ValueError` on malformed JSON and on a duplicate id (track seen ids). Build and validate each `ResearchDocument`, wrap as `IngestedDocument(document=..., text=...)`.

- [ ] **Step 7: Update `tests/test_stubs.py`** — delete the `(nvd.load, (b"",), {})` tuple from `STUB_CALLS`; drop `nvd` from the `from secure_ai_research.ingestion import ...` line (keep `attack, kev, sigma`).

- [ ] **Step 8: Run tests, verify pass** — `pytest tests/test_nvd.py tests/test_stubs.py -v`; Expected: PASS. Then `ruff check . && black --check . && mypy`.

- [ ] **Step 9: Commit** (`git add` the new/changed files; message `feat(ingestion): parse NVD feed into IngestedDocuments with canonical integrity hash` + footer).

---

### Task 2: Chunking

**Files:**
- Modify: `src/secure_ai_research/retrieval/chunking.py`
- Test: `tests/test_chunking.py`
- Modify: `tests/test_stubs.py` (drop the `chunking.chunk` row)

**Interfaces:**
- Produces: `chunk(text: str, *, size: int = 800, overlap: int = 150) -> list[str]`.

- [ ] **Step 1: Write the failing tests** in `tests/test_chunking.py`:
  - `test_short_text_is_one_chunk`: `chunk("one short sentence.") == ["one short sentence."]`.
  - `test_empty_text_is_no_chunks`: `chunk("") == []` and `chunk("   ") == []`.
  - `test_long_text_splits_with_overlap`: build `text` of ~50 space-separated words long enough to exceed `size=40` (call with `size=40, overlap=10`); assert `len(result) > 1`, every chunk `len <= 40`, consecutive chunks share at least one word (overlap), and the concatenation in order covers every word of the input (no word dropped).
  - `test_chunking_is_deterministic`: two calls with the same args are equal.

- [ ] **Step 2: Run, verify fail** — `pytest tests/test_chunking.py -v`; Expected: FAIL (`NotImplementedError`).

- [ ] **Step 3: Implement `chunk`** in `retrieval/chunking.py` — word-aware overlapping windows:

```python
def chunk(text: str, *, size: int = 800, overlap: int = 150) -> list[str]:
    words = text.split()
    if not words:
        return []
    chunks, start = [], 0
    while start < len(words):
        cur, i = [], start
        while i < len(words) and sum(len(w) for w in cur) + len(cur) + len(words[i]) <= size:
            cur.append(words[i]); i += 1
        if not cur:  # a single word longer than size
            cur, i = [words[start]], start + 1
        chunks.append(" ".join(cur))
        if i >= len(words):
            break
        back = 0  # step back ~overlap chars worth of whole words
        while back < len(cur) - 1 and sum(len(w) for w in cur[-(back + 1):]) <= overlap:
            back += 1
        start = i - back
    return chunks
```

- [ ] **Step 4: Run, verify pass** — `pytest tests/test_chunking.py -v`; Expected: PASS.

- [ ] **Step 5: Update `tests/test_stubs.py`** — delete the `(chunking.chunk, ("",), {})` tuple; drop `chunking` from the `from secure_ai_research.retrieval import ...` line.

- [ ] **Step 6: Commit** (`pytest && ruff check . && black --check . && mypy` first; message `feat(retrieval): implement deterministic overlapping chunking` + footer).

---

### Task 3: Ports + `HashingEmbedder` (+ `OllamaEmbedder` stub)

**Files:**
- Create: `src/secure_ai_research/retrieval/ports.py`
- Modify: `src/secure_ai_research/retrieval/embeddings.py`
- Test: `tests/test_embeddings.py`
- Modify: `tests/test_stubs.py` (drop `embeddings.embed` row; add adapter-stub test)

**Interfaces:**
- Produces, in `ports.py`:
  - `@dataclass(frozen=True) class ChunkRecord: chunk_id: str; document_id: str; text: str; embedding: list[float]`
  - `@dataclass(frozen=True) class ChunkHit: document_id: str; text: str; score: float`
  - `class Embedder(Protocol): def embed(self, chunks: list[str]) -> list[list[float]]: ...`
  - `class VectorStore(Protocol): def upsert(self, entries: list[ChunkRecord]) -> None: ...; def query(self, embedding: list[float], *, allowed_document_ids: set[str], limit: int) -> list[ChunkHit]: ...`
- Produces, in `embeddings.py`: `class HashingEmbedder` (implements `Embedder`, `DIM = 256`); `class OllamaEmbedder` (fail-loud).

- [ ] **Step 1: Write the failing tests** in `tests/test_embeddings.py`:
  - `test_embed_is_deterministic`: `HashingEmbedder().embed(["sql injection"])` equals a second call.
  - `test_embed_dimension_and_normalized`: each vector has length `256`; for non-empty text the L2 norm is `pytest.approx(1.0)`.
  - `test_shared_tokens_score_higher`: with `e = HashingEmbedder()`, cosine of `"sql injection in login"` vs `"sql injection database"` > cosine vs `"unrelated weather forecast"` (define a local cosine helper in the test).
  - `test_zero_vector_for_tokenless_text` *(Review Focus 2)*: `HashingEmbedder().embed(["!!! ??? ..."])[0]` is all-zeros, length 256 (no crash).
  - `test_ollama_embedder_is_fail_loud`: `OllamaEmbedder()` raises `NotImplementedError` containing `"ROADMAP Phase"`.

- [ ] **Step 2: Run, verify fail** — `pytest tests/test_embeddings.py -v`; Expected: FAIL (`embed` module-fn raises / classes missing).

- [ ] **Step 3: Create `ports.py`** with the two dataclasses and two `Protocol`s above (`from typing import Protocol`, `runtime_checkable` not required).

- [ ] **Step 4: Rewrite `embeddings.py`** — remove the module-level `embed` function; add `HashingEmbedder`:

```python
DIM = 256
def _bucket(tok: str) -> int:
    return int.from_bytes(hashlib.sha1(tok.encode("utf-8")).digest()[:4], "big") % DIM
class HashingEmbedder:
    def embed(self, chunks: list[str]) -> list[list[float]]:
        out = []
        for text in chunks:
            vec = [0.0] * DIM
            for tok in re.findall(r"[a-z0-9]+", text.lower()):
                vec[_bucket(tok)] += 1.0
            norm = math.sqrt(sum(v * v for v in vec))
            out.append([v / norm for v in vec] if norm else vec)
        return out
```
  Add `class OllamaEmbedder` whose `__init__` raises `NotImplementedError("Local embeddings via Ollama — ROADMAP Phase 2 (weeks 5-8): next slice wires the real nomic-embed-text adapter")`.

- [ ] **Step 5: Run, verify pass** — `pytest tests/test_embeddings.py -v`; Expected: PASS.

- [ ] **Step 6: Update `tests/test_stubs.py`** — delete the `(embeddings.embed, ([],), {})` tuple; drop `embeddings` from the retrieval import. Add:

```python
def test_adapter_stubs_raise_on_construction():
    from secure_ai_research.retrieval.embeddings import OllamaEmbedder
    with pytest.raises(NotImplementedError) as exc:
        OllamaEmbedder()
    assert "ROADMAP Phase" in str(exc.value)
```

- [ ] **Step 7: Commit** (`pytest && ruff check . && black --check . && mypy` first; message `feat(retrieval): add Embedder/VectorStore ports and deterministic HashingEmbedder` + footer).

---

### Task 4: `InMemoryVectorStore` (+ `PgVectorStore` stub)

**Files:**
- Modify: `src/secure_ai_research/retrieval/vectorstore.py`
- Test: `tests/test_vectorstore.py`
- Modify: `tests/test_stubs.py` (drop `vectorstore.upsert` + `vectorstore.retrieve` rows; extend adapter-stub test)

**Interfaces:**
- Consumes: `ports.ChunkRecord`, `ports.ChunkHit`, `ports.VectorStore`.
- Produces: `class InMemoryVectorStore` (implements `VectorStore`); `class PgVectorStore` (fail-loud).

- [ ] **Step 1: Write the failing tests** in `tests/test_vectorstore.py` (build `ChunkRecord`s with hand-written embeddings so ranking is exact, e.g. `[1.0, 0.0]`, `[0.0, 1.0]`):
  - `test_query_ranks_by_cosine`: upsert records for docs `A`,`B`; query close to `A`'s vector with `allowed_document_ids={"A","B"}, limit=2` → first hit `document_id == "A"`, scores descending.
  - `test_allowed_ids_filters_out_of_scope`: same store, query with `allowed_document_ids={"B"}` → every hit has `document_id == "B"` (A excluded).
  - `test_empty_allowed_set_returns_nothing`: `allowed_document_ids=set()` → `[]`.
  - `test_limit_respected`: `limit=1` → exactly one hit.
  - `test_zero_norm_query_does_not_crash` *(Review Focus 2)*: query embedding all zeros → returns a list (possibly all score `0.0`), no exception.

- [ ] **Step 2: Run, verify fail** — `pytest tests/test_vectorstore.py -v`; Expected: FAIL.

- [ ] **Step 3: Rewrite `vectorstore.py`** — remove the module-level `upsert`/`retrieve`; add `InMemoryVectorStore` holding a `list[ChunkRecord]` (`upsert` appends; `query` computes cosine against records whose `document_id in allowed_document_ids`, sorts by score descending, returns the top `limit` as `ChunkHit`s). Cosine helper returns `0.0` when either norm is `0`. Add `class PgVectorStore` whose `__init__` raises `NotImplementedError("Vector store via Postgres/pgvector — ROADMAP Phase 2 (weeks 5-8): next slice wires the real adapter")`.

- [ ] **Step 4: Run, verify pass** — `pytest tests/test_vectorstore.py -v`; Expected: PASS.

- [ ] **Step 5: Update `tests/test_stubs.py`** — delete the `vectorstore.upsert` and `vectorstore.retrieve` tuples; drop `vectorstore` from the retrieval import (the line is now empty — remove it). Extend `test_adapter_stubs_raise_on_construction` to also assert `PgVectorStore()` raises with `"ROADMAP Phase"`.

- [ ] **Step 6: Commit** (`pytest && ruff check . && black --check . && mypy` first; message `feat(retrieval): add InMemoryVectorStore with scope-filtered cosine query` + footer).

---

### Task 5: Authorization gate

**Files:**
- Modify: `src/secure_ai_research/retrieval/authz.py`
- Test: `tests/test_authz.py`
- Modify: `tests/test_stubs.py` (drop `authz.authorize` row)

**Interfaces:**
- Consumes: `ingestion.schema.ResearchDocument`, `Classification`.
- Produces: `authorize(role: str, doc: ResearchDocument) -> bool`.

- [ ] **Step 1: Write the failing tests** in `tests/test_authz.py` (build a PUBLIC `ResearchDocument` fixture via a small helper):
  - `test_permitted_roles`: `authorize("research_analyst", doc)` and `authorize("senior_analyst", doc)` are `True`.
  - `test_denied_roles`: `authorize(r, doc)` is `False` for each of `"security_auditor"`, `"model_admin"`, `"data_steward"`, `"administrator"`, `"unknown"`, `""`.
  - `test_role_is_stripped`: `authorize("  research_analyst  ", doc)` is `True`.

- [ ] **Step 2: Run, verify fail** — `pytest tests/test_authz.py -v`; Expected: FAIL (`NotImplementedError`).

- [ ] **Step 3: Implement `authorize`** in `authz.py` — `_ALLOWED = {"research_analyst", "senior_analyst"}`; `return role.strip() in _ALLOWED and doc.classification == Classification.PUBLIC` (role allows **and** the document's attributes permit — the ABAC shape from `roles.md`). Remove the `TYPE_CHECKING`-only import guard as needed so `Classification` is importable at runtime.

- [ ] **Step 4: Run, verify pass** — `pytest tests/test_authz.py -v`; Expected: PASS.

- [ ] **Step 5: Update `tests/test_stubs.py`** — delete the `(authz.authorize, ...)` tuple; drop `authz` from (and thus remove) the retrieval import line.

- [ ] **Step 6: Commit** (`pytest && ruff check . && black --check . && mypy` first; message `feat(retrieval): implement deny-by-default authorization allowlist` + footer).

---

### Task 6: Report rendering

**Files:**
- Modify: `src/secure_ai_research/reporting/report.py`
- Test: `tests/test_report.py`
- Modify: `tests/test_stubs.py` (drop `report.build_report` row)

**Interfaces:**
- Consumes: `audit.record.ResearchRecord`.
- Produces: `build_report(record: ResearchRecord) -> str`.

- [ ] **Step 1: Write the failing tests** in `tests/test_report.py` (construct a `ResearchRecord` directly with all required fields set, `retrieved_doc_ids=["CVE-2099-0001"]`):
  - `test_report_includes_cited_claim`: `model_output = "A synthetic SQL injection. [CVE-2099-0001]"`; report contains that claim text and a `Sources:` line listing `CVE-2099-0001`, and includes the `objective`.
  - `test_uncited_claim_line_dropped`: `model_output = "Cited thing. [CVE-2099-0001]\nUncited editorializing with no citation."`; report contains `"Cited thing."` but **not** `"Uncited editorializing"`.
  - `test_claim_citing_unknown_id_dropped`: a line citing `[CVE-2099-9999]` (not in `retrieved_doc_ids`) is dropped.
  - `test_no_cited_claims_states_no_findings`: `model_output = ""` → report body states no cited findings (a fixed phrase, not fabricated content).

- [ ] **Step 2: Run, verify fail** — `pytest tests/test_report.py -v`; Expected: FAIL (`NotImplementedError`).

- [ ] **Step 3: Implement `build_report`** in `report.py` — split `model_output` into non-empty lines; a line is **kept** iff it contains ≥1 `[id]` token (regex `\[([^\]]+)\]`) and every cited id is in `set(record.retrieved_doc_ids)`. Render `f"# Research report: {record.objective}"`, blank line, the kept lines (or the fixed phrase `"No cited findings."` when none), blank line, `f"Sources: {', '.join(record.retrieved_doc_ids)}"`. Remove the `TYPE_CHECKING` guard if a runtime import is needed.

- [ ] **Step 4: Run, verify pass** — `pytest tests/test_report.py -v`; Expected: PASS.

- [ ] **Step 5: Update `tests/test_stubs.py`** — delete the `(report.build_report, (None,), {})` tuple; remove the now-unused `from secure_ai_research.reporting import report` import.

- [ ] **Step 6: Commit** (`pytest && ruff check . && black --check . && mypy` first; message `feat(reporting): render cited report, dropping uncited claims` + footer).

---

### Task 7: `ResearchService` orchestration

**Files:**
- Create: `src/secure_ai_research/research_service.py`
- Test: `tests/test_research_service.py`

**Interfaces:**
- Consumes: `IngestedDocument`; `chunking.chunk`; `ports.Embedder`/`HashingEmbedder`; `ports.VectorStore`/`InMemoryVectorStore`/`ChunkRecord`; `authz.authorize`; `reporting.build_report`; `audit.record.ResearchRecord`/`emit`/`read_records`; `nvd.load` (tests build the corpus from the fixture).
- Produces:
  - `class Outcome(StrEnum): OK; DENIED; NOT_FOUND`
  - `@dataclass(frozen=True) class Citation: document_id: str; source_url: str; passage: str`
  - `@dataclass(frozen=True) class ResearchResult: outcome: Outcome; answer: str; citations: list[Citation]; research_id: str`
  - `class ResearchService` with `__init__(self, embedder: Embedder, store: VectorStore, authorize: Callable[[str, ResearchDocument], bool], audit_path: Path, limit: int = 5)`, `index(self, docs: list[IngestedDocument]) -> None`, `research_cve(self, cve_id: str, *, role: str) -> ResearchResult`.

- [ ] **Step 1: Write the failing tests** in `tests/test_research_service.py`. Shared fixture: load the two synthetic docs via `nvd.load`, build `svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, tmp_path/"audit.jsonl")`, `svc.index(docs)`.
  - `test_permitted_role_gets_cited_answer`: `res = svc.research_cve("CVE-2099-0001", role="research_analyst")`; `res.outcome is Outcome.OK`; `res.answer` contains `"CVE-2099-0001"`; `res.citations` has one whose `document_id == "CVE-2099-0001"` and `source_url == "https://nvd.nist.gov/vuln/detail/CVE-2099-0001"`. `read_records(audit)` has one record with `analyst_id == "research_analyst"`, `data_source_ids == ["NVD"]`, `model_id == "retrieval-only"`, `retrieved_doc_ids == ["CVE-2099-0001"]`, and `research_id == res.research_id`.
  - `test_denied_role_never_queries_store` *(Review Focus 4)*: wrap the store in a spy that counts `query` calls; `res = svc.research_cve("CVE-2099-0001", role="")`; `res.outcome is Outcome.DENIED`; `res.citations == []`; the spy's query-count is `0`; the emitted record has `retrieved_doc_ids == []` and `document_hashes == []`.
  - `test_absent_cve_is_not_found` *(Review Focus 4)*: `res = svc.research_cve("CVE-2099-9999", role="research_analyst")`; `res.outcome is Outcome.NOT_FOUND`; emitted record has empty `retrieved_doc_ids`/`document_hashes`.
  - `test_multiline_answer_round_trips_as_one_record` *(Review Focus 3)*: after a permitted call whose `answer`/`model_output` spans multiple lines, `len(read_records(audit)) == 1`.

- [ ] **Step 2: Run, verify fail** — `pytest tests/test_research_service.py -v`; Expected: FAIL (module missing).

- [ ] **Step 3: Implement `research_service.py`.** `index`: for each `IngestedDocument`, `chunk(text)` → `embedder.embed(chunks)` → `store.upsert([ChunkRecord(f"{id}#{i}", id, chunk_i, vec_i) ...])`; keep `self._docs: dict[str, ResearchDocument]`. `research_cve`:
  1. `allowed = {did for did, doc in self._docs.items() if self._authorize(role, doc)}`.
  2. if `not allowed`: emit a DENIED record (see below) and return `ResearchResult(Outcome.DENIED, "", [], rid)`. **(store not queried)**
  3. if `cve_id not in self._docs`: emit a NOT_FOUND record, return `ResearchResult(Outcome.NOT_FOUND, "", [], rid)`.
  4. `hits = self._store.query(self._embedder.embed([cve_id])[0], allowed_document_ids=(allowed & {cve_id}), limit=self._limit)`.
  5. dedup hits by `document_id` in rank order → ordered doc ids; `citations = [Citation(did, str(doc.source_url), first_hit_text_for_did) ...]`; `model_output = "\n".join(f"{hit.text} [{hit.document_id}]" for hit in hits)`.
  6. build the OK `ResearchRecord` (`retrieved_doc_ids = ordered ids`, `document_hashes = [doc.integrity_hash ...]`, `data_source_ids = sorted({doc.source ...})`, `model_id="retrieval-only"`, `model_version=""`, `prompt_template_version=""`, `conclusion="retrieval-only: assembled from cited passages"`), `answer = build_report(record)`, `emit(record, path)`, return `ResearchResult(Outcome.OK, answer, citations, rid)`.
  - Shared record fields: `research_id = rid = uuid.uuid4().hex`, `analyst_id = role.strip() or "anonymous"`, `timestamp = datetime.now(timezone.utc)`, `objective = f"Correlate {cve_id} against public sources"`. DENIED/NOT_FOUND records set empty `data_source_ids`/`document_hashes`/`retrieved_doc_ids`, `model_id="retrieval-only"`, and a `conclusion` naming only the outcome.

- [ ] **Step 4: Run, verify pass** — `pytest tests/test_research_service.py -v`; Expected: PASS.

- [ ] **Step 5: Commit** (`pytest && ruff check . && black --check . && mypy` first; message `feat: add ResearchService (authorize-before-retrieve, cited answer, audit)` + footer).

---

### Task 8: API wiring — `GET /research/cve/{cve_id}`

**Files:**
- Create: `src/secure_ai_research/api/deps.py`
- Modify: `src/secure_ai_research/api/routers/research.py`
- Test: `tests/test_api.py` (replace `test_research_cve_501`; keep `test_research_search_501`)

**Interfaces:**
- Consumes: `ResearchService`, `Outcome`; `HashingEmbedder`, `InMemoryVectorStore`, `authz.authorize`, `nvd.load`, the packaged fixture, `config.get_settings`.
- Produces: `get_service() -> ResearchService` (FastAPI dependency); an implemented `GET /research/cve/{cve_id}`.

- [ ] **Step 1: Write the failing tests** in `tests/test_api.py`. Add a fixture that builds a service on a `tmp_path` audit log with the fixture indexed, and installs it via `app.dependency_overrides[get_service] = lambda: that_service` (teardown clears the override). Delete `test_research_cve_501`. Add:
  - `test_cve_permitted_returns_cited_answer`: `client.get("/research/cve/CVE-2099-0001", headers={"X-Role": "research_analyst"})` → `200`; body has non-empty `answer`, `citations[0]["document_id"] == "CVE-2099-0001"`, and a `research_id`.
  - `test_cve_missing_role_denied`: no `X-Role` header → `403`.
  - `test_cve_unknown_role_denied`: `X-Role: security_auditor` → `403`.
  - `test_cve_absent_is_404` *(Review Focus 5)*: `CVE-2099-9999` with `X-Role: research_analyst` → `404`.
  - `test_cve_malformed_is_422` *(Review Focus 5)*: `/research/cve/not-a-cve` → `422`.
  - Keep `test_research_search_501` unchanged.

- [ ] **Step 2: Run, verify fail** — `pytest tests/test_api.py -v`; Expected: FAIL (`get_service` missing / endpoint still 501 / old test gone).

- [ ] **Step 3: Implement `api/deps.py`** — `@lru_cache def get_service() -> ResearchService:` builds `ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, get_settings().audit_log_path)`, reads the packaged fixture via `importlib.resources`, and `index(nvd.load(raw))` before returning.

- [ ] **Step 4: Implement the route** in `api/routers/research.py` (imports: add `Depends, Header, Path` from `fastapi`, `JSONResponse` from `fastapi.responses`, `asdict` from `dataclasses`, plus `get_service` and `Outcome`). Replace `research_cve` with a handler returning `JSONResponse`, so the error bodies match the design's `{detail, research_id}` without nesting:

```python
def research_cve(
    cve_id: str = Path(pattern=r"^CVE-\d{4}-\d{4,}$"),
    x_role: str = Header(default=""),
    service: ResearchService = Depends(get_service),
) -> JSONResponse:
    res = service.research_cve(cve_id, role=x_role)
    if res.outcome is Outcome.OK:
        return JSONResponse(status_code=200, content={
            "answer": res.answer,
            "citations": [asdict(c) for c in res.citations],
            "research_id": res.research_id,
        })
    if res.outcome is Outcome.DENIED:
        return JSONResponse(status_code=403, content={"detail": "role not authorized", "research_id": res.research_id})
    return JSONResponse(status_code=404, content={"detail": f"no document for {cve_id}", "research_id": res.research_id})
```
  A malformed `cve_id` is rejected 422 by the `Path(pattern=...)` validation before the body runs. Leave `/attack` and `/search` as the existing 501 stubs.

- [ ] **Step 5: Run, verify pass** — `pytest tests/test_api.py -v`; Expected: PASS.

- [ ] **Step 6: Full gate** — `pytest` (whole suite), `ruff check .`, `black --check .`, `mypy`; Expected: all green.

- [ ] **Step 7: Commit** (message `feat(api): wire GET /research/cve/{id} to ResearchService with role gate` + footer).
