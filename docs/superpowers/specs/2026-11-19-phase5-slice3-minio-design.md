# Phase 5 Slice 3 — MinIO object store for raw payloads (Design)

**Status:** proposed (awaiting Chris's approval — the one gate before build)
**Date:** 2026-11-19
**Repo:** `/Users/fox/Chris/CyberBase/secure-ai-research` (local git, no remote, main@eaa3c85)
**Prior art:** Slice 2 (`PgVectorStore` behind the `VectorStore` seam) sets the exact pattern this slice mirrors for a new `ObjectStore` seam: Protocol + in-memory default + opt-in real adapter via an env flag, lazy-imported, fail-closed to one audit record.

---

## 1. Intent & why

The platform's thesis is **evidence-grounded, provenance-backed** research. Every ingested document already carries `integrity_hash = "sha256:" + sha256(canonical)` over its **canonical source object** (computed in each loader, folded into `ResearchDocument.integrity_hash`). But the bytes *behind* that hash are computed, hashed, and **thrown away** — so today the chain of custody is a hash with nothing to verify it against.

This slice adds a **content-addressed object store that durably retains the canonical bytes of every indexed document**, keyed by the `integrity_hash` already on the record. That closes the provenance loop at the write side: the exact bytes a hash commits to are retained and content-verifiable.

**Why now:** next slice in the agreed 8-slice Phase-5 batch, and the infra is already provisioned — `docker-compose.yml` ships a `minio` service (loopback-bound `127.0.0.1:9000`, console `:9001`, `minio-data` volume, healthchecked) and `config.py` already carries `minio_endpoint / minio_access_key / minio_secret_key`. Nothing new needs provisioning to test it.

**Scope decision (Chris, 2026-11-19):** Approach **A** — a write-side provenance sink with **no new read endpoint**. Serving/verifying raw payloads to a user is the natural *next* slice and deserves its own authz + sensitivity design; it is explicitly out of scope here.

---

## 2. Goals / Non-goals / Anti-goals

### Goals
- A new `ObjectStore` Protocol (`put`, `get`) with two implementations: `InMemoryObjectStore` (deterministic, dependency-free, **default**) and `MinioObjectStore` (opt-in, real).
- Opt-in selection via `SAIR_OBJECT_STORE=minio`; default `memory`. A `make_object_store(settings)` factory, mirroring `make_vector_store`.
- Each loader (nvd, attack, kev, sigma) **retains** the `canonical` bytes it already computes, carried on `IngestedDocument`.
- `ResearchService` persists `object_store.put(integrity_hash, canonical)` for each document at index time, **before** the vector upsert (provenance-first), so nothing becomes queryable without its provenance bytes retained first.
- **Fail-closed on the request path:** an object-store fault during fetch-on-miss re-index surfaces as `FETCH_ERROR` → 503 with **exactly one audit record** (exception type only), identical to the Slice-2 store-fault contract.
- **Default path byte-identical:** with no env flag, query/search/ask/cve results are unchanged, no new runtime dependency is imported, and the hermetic suite never imports `minio`.

### Non-goals (explicitly out of this slice)
- **No read/serve endpoint** (`GET /research/raw/...`) and no verify-on-read. That is Approach C, the next slice.
- **No change to the existing `CachingCveSource`** NVD live-fetch disk cache (`nvd_cache_dir`). That caches raw *feed* bytes for the opt-in live-fetch path; it is orthogonal and stays as-is.
- **No filesystem object store.** Two implementations only (in-memory default + minio opt-in), mirroring Slice 2's shape. A filesystem tier is YAGNI.
- **No schema migrations**, no bucket lifecycle/retention policy, no object versioning.
- **No sensitivity/authz gate on the store** — because nothing reads from it on a request path, there is no disclosure surface to gate (see §8).

### Anti-goals (a failure even if it "works")
- Provenance **silently skipped** when the store faults (must fail closed, never best-effort-and-continue).
- `minio` imported on the default path, or the hermetic suite importing it.
- **Hash/bytes drift:** storing bytes `b` under key `sha256:h` where `sha256(b) != h`. The stored object must always satisfy its own key.
- Any backend message or payload bytes leaking into the audit trail (type-tag only).

---

## 3. Constraints (inherited, verbatim where pinned)

- **PUBLIC / synthetic data only**; never commit secrets, `.env`, data, or weights. Canonical payloads are PUBLIC corpus bytes.
- **Default must stay offline / deterministic / dependency-free.** `minio` is an **optional extra**, lazily imported inside the adapter's `__init__`.
- **One audit record per request path**; an unhandled 500 with zero audit records is a core-invariant violation.
- Errors carry an **exception-type tag only** — no backend string, no payload.
- **mypy** `files=["src"]`, `ignore_missing_imports=true` (lazy `minio` needs no stub). **ruff** select E,F,I,UP,B, line-length 100. **pytest** `addopts=["-m","not integration"]`; `integration` marker registered; deselected files are still collected, so `minio` is imported only inside functions in the integration test.
- **No push** — repo stays local; merge-to-main-local at finish.

---

## 4. Current state (what the change touches)

- **Loaders** `ingestion/{nvd,attack,kev,sigma}.py`: each builds `canonical = json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()`, computes `integrity_hash`, then **discards** `canonical`. `load()` returns `list[IngestedDocument]`.
- **`ingestion/ingested.py`**: `IngestedDocument` is a frozen dataclass `{document: ResearchDocument, text: str}`. `ResearchDocument` (schema.py) is metadata-only and carries `integrity_hash` (`^sha256:[0-9a-f]{64}$`).
- **`research_service.py`**: constructor `ResearchService(embedder, store, authorize, audit_path, limit=5, *, fetch_missing=None, generator=None)`. `_index_one(item)` chunks → embeds → `self._store.upsert(...)` → publishes `self._docs[id]=doc` **last**. `index()` (boot/ingest) raises on duplicate id; `_index_if_absent()` (fetch-on-miss, holds the lock) skips already-present ids. The live-fetch call `self._index_if_absent(fetched)` inside `research_cve` is **already wrapped** (Slice 2) in a two-arm `except VectorStoreError / except Exception` → `_emit_terminal(... "fetch_error ...")` + `FETCH_ERROR`.
- **`api/deps.py`**: builds the service with `make_vector_store(settings)`; no object store today.
- **`config.py`**: has `minio_endpoint / minio_access_key / minio_secret_key`; no `object_store` selector and no bucket name.
- **Infra**: `docker-compose.yml` `minio` service already present; no code references it.

---

## 5. Approaches considered

**A — Provenance sink at the index boundary (CHOSEN).** `ObjectStore` seam; at index time persist each doc's canonical bytes keyed by `integrity_hash`. No request-path read, so the store being down never breaks search/ask (only fetch-on-miss re-index, which already fails closed). Zero new attack surface; default byte-identical. Trade-off: provenance is retained but not yet *served* (next slice).

**B — Back the live-fetch cache with the seam (rejected).** Replace `CachingCveSource`'s disk feed-cache with the object store. Narrowest value: serves only the opt-in, default-off NVD live-fetch path, and does **not** retain provenance for the fixture corpus (≈all of what is indexed). Couples a general provenance capability to a narrow feature.

**C — Full provenance: retain + serve + verify (deferred to next slice).** A plus a role- and sensitivity-gated `GET /research/raw/{hash}`. Highest value but adds a new info-disclosure channel that must traverse the full authz + sensitivity + audit stack; warrants its own design. Deferred, not rejected.

---

## 6. Decided design (the how)

### 6.1 Component map
- **New package** `src/secure_ai_research/storage/`:
  - `ports.py` — `ObjectStore` Protocol + `ObjectStoreError(Exception)`.
  - `objectstore.py` — `InMemoryObjectStore`, `MinioObjectStore`.
  - `factory.py` — `make_object_store(settings) -> ObjectStore` (default in-memory; `minio` lazily imported only in the minio branch).
- **`ingestion/ingested.py`** — add `canonical: bytes = b""` (last field; frozen dataclass).
- **Loaders** nvd/attack/kev/sigma — pass `canonical=canonical` into the `IngestedDocument(...)` they already build (one-line change each; `canonical` already exists as a local).
- **`config.py`** — add `object_store: Literal["memory", "minio"] = "memory"` and `minio_bucket: str = "sair-raw"`.
- **`api/deps.py`** — construct `make_object_store(settings)` and pass it to `ResearchService`.
- **`research_service.py`** — new keyword-only `object_store: ObjectStore | None = None` (→ `self._object_store = object_store or InMemoryObjectStore()`); add the `put` in `_index_one`; add an explicit `except ObjectStoreError` arm to the existing live-fetch wrap.

### 6.2 `ObjectStore` Protocol (`storage/ports.py`)
```python
class ObjectStore(Protocol):
    def put(self, key: str, data: bytes) -> None: ...   # idempotent overwrite (content-addressed)
    def get(self, key: str) -> bytes: ...               # raises ObjectStoreError if absent/faulted

class ObjectStoreError(Exception): ...
```
`key` is the `integrity_hash` verbatim (`sha256:<64hex>`). `put` is idempotent: the same key always carries the same bytes, so overwrite-on-conflict is correct and a boot re-index is a no-op in effect. `get` exists for round-trip verification in tests and as the seam C will build on; no request path calls it this slice.

### 6.3 `InMemoryObjectStore`
A dict `{key: bytes}`. `put` overwrites; `get` raises `ObjectStoreError` on a missing key. Deterministic, offline, never imports `minio`. This is the default and the hermetic-test store.

### 6.4 `MinioObjectStore` adapter
Mirrors `PgVectorStore`: lazy driver import, fail-closed, short-lived calls.
- `__init__(endpoint, access_key, secret_key, bucket, *, secure=False)`: `import minio` inside a try → on `ImportError` raise `ObjectStoreError("minio extra not installed: pip install '.[minio]'")`. Then build the client and `_ensure_bucket()` (`make_bucket` if `not bucket_exists`). Loopback minio is plain HTTP → `secure=False`.
- Object name derived from the key: `sha256:<hex>` → `sha256/<hex>` (replace `:` with `/`) for a tidy prefix; the mapping is internal to the adapter.
- `put`: `client.put_object(bucket, name, BytesIO(data), length=len(data))`.
- `get`: `client.get_object(...).read()` (raises `ObjectStoreError` if absent/faulted).
- **Every** boto/minio exception and connection fault is caught and re-raised as `ObjectStoreError(f"... ({type(exc).__name__})")` — type tag only, never a backend message.

### 6.5 Fail-closed wiring (`research_service.py`)
- In `_index_one`, **before** the vector upsert:
  ```python
  self._object_store.put(doc.integrity_hash, item.canonical)
  self._store.upsert([...])      # unchanged
  self._docs[doc.document_id] = doc   # published last, unchanged
  ```
  Ordering guarantees: provenance retained first → a `put` fault means no vector upsert and no `_docs` publish, so nothing is ever queryable without its provenance.
- **Boot/ingest `index()`**: a `put` fault propagates loud (no request context, no audit) — correct: never silently build a corpus without provenance.
- **Fetch-on-miss request path**: the existing wrap around `self._index_if_absent(fetched)` gains an explicit `except ObjectStoreError` arm (sibling of the `VectorStoreError` arm) → one `_emit_terminal(... "fetch_error: retrieval failed (ObjectStoreError)")` + `FETCH_ERROR`. (The broad `except Exception` arm already present catches it too; the typed arm is parity + clarity.) Import `ObjectStoreError` alongside `VectorStoreError`.

### 6.6 Dependency as an optional extra (`pyproject.toml`)
`[project.optional-dependencies].minio = ["minio>=7.2,<8.0"]`. Not in the base deps; hermetic suite never installs or imports it.

### 6.7 Provenance semantics (honest)
- **Default (`memory`)**: canonical bytes held in RAM, re-populated on each boot re-index — deterministic and offline, but ephemeral. Durable retention is the opt-in minio tier's job (parity with Slice 2's in-memory-vs-pgvector framing).
- **`minio`**: durable, content-addressed retention surviving restarts.
- No read surface either way this slice.

---

## 7. Testing strategy

**Hermetic (default suite — no minio, no `minio` import):**
1. **Loader canonical round-trip** (one per loader, or a parametrized test): `ingested.canonical` is non-empty and `sha256(ingested.canonical).hexdigest() == ingested.document.integrity_hash.removeprefix("sha256:")`. (Review Focus #4.)
2. **Service persists provenance**: a spy/in-memory store receives `put(integrity_hash, canonical)` for each indexed doc, keyed correctly, before the vector upsert.
3. **Fail-closed on put fault**: an armed raising object store on a fetch-on-miss re-index → `FETCH_ERROR`, empty answer, **exactly one** audit record, no backend/payload string in the log. (Review Focus #1 — the Slice-2 fix's sibling.)
4. **Lazy import**: importing `storage.objectstore` does not import `minio` (skip if already loaded); constructing `MinioObjectStore` without the extra raises `ObjectStoreError` naming the extra. (Review Focus #2, #3.)
5. **Factory default**: `make_object_store(Settings())` is `InMemoryObjectStore`; `SAIR_OBJECT_STORE=minio` selects the minio branch (asserted without connecting, e.g. via the missing-extra/monkeypatched path).
6. **Default path unchanged**: an existing search/ask/cve result is byte-identical with the object store wired (in-memory), no `minio` import. (Review Focus #5.)

**Integration (`-m integration`, excluded by default/CI; skips cleanly without minio):**
- Round-trip `put`/`get` against live minio (`docker compose up -d minio`, `pip install -e '.[minio]'`): bytes returned equal bytes stored.
- `_ensure_bucket` creates the bucket when absent; idempotent on re-run.
- `put` is idempotent (same key twice → one object, latest bytes).
- Bad endpoint → `ObjectStoreError`.
- `minio` imported only inside functions (module import-safe for the hermetic collector).

**Test command:** `./.venv/bin/pytest -q -m "not integration"` (hermetic); `./.venv/bin/pytest -q -m integration` (real minio, after `pip install -e '.[minio]'` + `docker compose up -d minio`).

---

## 8. Security / threat notes

- **No new read surface.** Approach A writes provenance only; nothing on a request path reads the store, so no information-disclosure channel is added and no sensitivity/authz gate is needed on it. (Serving raw payloads — C — would require the RESTRICTED→senior-only gate and its own info-disclosure tests; deferred.)
- **Fail-closed.** A store outage on the live-fetch request path is `FETCH_ERROR` + one audit record, never a silent provenance gap and never an unhandled 500. At boot it is loud.
- **No leak.** Errors carry only the exception type; canonical payload bytes (PUBLIC, but still) and any backend message never reach the audit log.
- **Credentials** come from env/settings (`minio_*`), never committed; the loopback default is dev-only.
- **Integrity.** The stored object is keyed by the hash it satisfies; a loader test pins `sha256(bytes)==hash` so stored provenance can never silently drift from the committed record.

---

## 9. ROADMAP accounting (honest)

- Tick Week 5 — "Object store (MinIO) for raw payloads" (the retention half). Note in the line: write-side provenance sink; serving/verify deferred to the next slice.
- Schema **migrations** (Alembic) remain unchecked/deferred (unchanged).

---

## 10. Review Focus (most likely to bite; each gets a test in its owning task)

1. **Object-store fault on fetch-on-miss re-index** → must be `FETCH_ERROR` + exactly one audit record, never an unhandled 500. (service task)
2. **Importing the storage module must not import `minio`** (lazy-import posture). (storage task)
3. **Missing `[minio]` extra** → clear `ObjectStoreError` naming the extra, not a bare `ImportError`. (storage task)
4. **Canonical/hash integrity**: every loader's stored `canonical` satisfies `sha256(canonical)==integrity_hash`. (loader task)
5. **Default path (`SAIR_OBJECT_STORE` unset) is byte-identical**: search/ask/cve unchanged, no `minio` import, provenance `put` goes to the in-memory store. (factory/wiring task)

---

## 11. What's left to the builder

- Exact minio object-naming (the `sha256:<hex>` → `sha256/<hex>` mapping is a suggestion; any stable, collision-free mapping is fine).
- Whether to add a cheap `exists(key)` to skip re-`put` on boot re-index (optimization only; not required — `put` is idempotent).
- Whether the service should defensively raise on an empty `canonical` before `put` (loader tests already guarantee non-empty; builder's discretion).
- The `secure` flag plumbing (loopback default is `secure=False`; a `minio_secure` setting can be added if a real deployment needs TLS — out of scope here).
- Connect/timeout value for the minio client; exact test file names and parametrization.
- Task decomposition and commit boundaries (the plan's job).
