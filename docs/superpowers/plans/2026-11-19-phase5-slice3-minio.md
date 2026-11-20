# Phase 5 Slice 3 — MinIO object store for raw payloads — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Durably retain every indexed document's canonical source bytes in a content-addressed object store keyed by its existing `integrity_hash`, behind a new `ObjectStore` seam (in-memory default, opt-in MinIO), failing closed on any store fault.

**Architecture:** New `storage/` package mirrors `retrieval/`: an `ObjectStore` Protocol with an `InMemoryObjectStore` default and an opt-in `MinioObjectStore` (lazy-imported, fail-closed), selected by `make_object_store(settings)`. Loaders retain the `canonical` bytes they already hash; `ResearchService` persists them at the index boundary, provenance-first (before the vector upsert). A store fault on the fetch-on-miss request path surfaces as `FETCH_ERROR` + exactly one audit record — the Slice-2 contract.

**Tech Stack:** Python 3.12, pydantic Settings, the official `minio` SDK (optional extra), pytest (hermetic + `-m integration`), ruff/mypy.

**Spec:** `docs/superpowers/specs/2026-11-19-phase5-slice3-minio-design.md`

## Global Constraints

- PUBLIC/synthetic data only; never commit secrets/.env/data/weights.
- Default path stays offline/deterministic/dependency-free; `minio` is an optional extra, lazily imported inside `MinioObjectStore.__init__`; the hermetic suite never imports `minio`.
- Exactly one audit record per request path; an unhandled 500 with zero audit records is a core-invariant violation.
- Errors carry an exception-type tag only — never a backend message or payload bytes.
- mypy `files=["src"]`, `ignore_missing_imports=true`. ruff select E,F,I,UP,B, line-length 100.
- pytest `addopts=["-m","not integration"]`; `integration` marker registered; deselected files are still collected, so `minio` is imported only INSIDE functions in the integration test.
- Key passed to the store is the `integrity_hash` verbatim (`sha256:<64hex>`); `put` is an idempotent content-addressed overwrite.
- No push — repo stays local; merge-to-main-local at finish.

## Review Focus

Each line's test is attached to the task that owns the code.

1. **Object-store fault on fetch-on-miss re-index** → `FETCH_ERROR` + exactly one audit record, never an unhandled 500. → Task 4.
2. **Importing the storage module must NOT import `minio`** (lazy-import posture). → Task 3.
3. **Missing `[minio]` extra** → a clear `ObjectStoreError` naming the extra, not a bare `ImportError`. → Task 3.
4. **Canonical/hash integrity**: every loader's retained `canonical` satisfies `sha256(canonical).hexdigest() == integrity_hash[7:]`. → Task 2.
5. **Default path (`SAIR_OBJECT_STORE` unset) byte-identical**: search/cve unchanged, no `minio` import, provenance `put` lands in the in-memory store. → Task 4.

---

### Task 1: `ObjectStore` seam + `ObjectStoreError` + `InMemoryObjectStore`

**Files:**
- Create: `src/secure_ai_research/storage/__init__.py` (empty)
- Create: `src/secure_ai_research/storage/ports.py`
- Create: `src/secure_ai_research/storage/objectstore.py`
- Test: `tests/test_object_store.py`

**Interfaces:**
- Produces:
  - `ObjectStore` Protocol: `put(self, key: str, data: bytes) -> None`; `get(self, key: str) -> bytes`.
  - `ObjectStoreError(Exception)`.
  - `InMemoryObjectStore` implementing `ObjectStore` — a `dict[str, bytes]`; `put` overwrites; `get` raises `ObjectStoreError` on a missing key.

- [ ] **Step 1: Write the failing tests** in `tests/test_object_store.py`:

```python
def test_put_then_get_round_trips():
    s = InMemoryObjectStore()
    s.put("sha256:" + "a" * 64, b"canonical-bytes")
    assert s.get("sha256:" + "a" * 64) == b"canonical-bytes"

def test_put_is_idempotent_overwrite():
    s = InMemoryObjectStore()
    s.put("k", b"one"); s.put("k", b"two")
    assert s.get("k") == b"two"

def test_get_missing_key_raises_object_store_error():
    with pytest.raises(ObjectStoreError):
        InMemoryObjectStore().get("absent")
```

- [ ] **Step 2: Run to verify they fail**
Run: `./.venv/bin/pytest tests/test_object_store.py -q`
Expected: FAIL (ImportError: cannot import `InMemoryObjectStore`/`ObjectStoreError`).

- [ ] **Step 3: Implement** `ObjectStore` Protocol + `ObjectStoreError` in `storage/ports.py`, and `InMemoryObjectStore` in `storage/objectstore.py` (dict-backed; `get` raises `ObjectStoreError(f"object not found: {key}")`). Add empty `storage/__init__.py`.

- [ ] **Step 4: Run to verify they pass**
Run: `./.venv/bin/pytest tests/test_object_store.py -q` — Expected: PASS. Then `./.venv/bin/ruff check src tests && ./.venv/bin/mypy` — Expected: clean.

- [ ] **Step 5: Commit**
```bash
git add src/secure_ai_research/storage tests/test_object_store.py
git commit -m "feat(storage): ObjectStore seam + ObjectStoreError + InMemoryObjectStore (Slice 3)"
```

---

### Task 2: Loaders retain `canonical` bytes on `IngestedDocument`

**Files:**
- Modify: `src/secure_ai_research/ingestion/ingested.py` (add field)
- Modify: `src/secure_ai_research/ingestion/{nvd,attack,kev,sigma}.py` (pass `canonical=canonical`)
- Test: `tests/test_loader_canonical.py`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `IngestedDocument.canonical: bytes` (frozen-dataclass field, default `b""`, declared LAST). Every loader sets it to the exact bytes it hashes for `integrity_hash`.

- [ ] **Step 1: Write the failing test** `tests/test_loader_canonical.py` — parametrized over the four loaders, each fed the packaged sample bytes its existing tests already use (`importlib.resources` from `secure_ai_research.ingestion.samples`):

```python
import hashlib
# params: (load_fn, sample_bytes) for nvd, attack, kev, sigma
def test_loader_retains_canonical_matching_its_hash(load_fn, sample_bytes):
    docs = load_fn(sample_bytes)
    assert docs
    for d in docs:
        assert d.canonical, "loader must retain canonical bytes"
        assert hashlib.sha256(d.canonical).hexdigest() == d.document.integrity_hash[len("sha256:"):]
```

- [ ] **Step 2: Run to verify it fails**
Run: `./.venv/bin/pytest tests/test_loader_canonical.py -q`
Expected: FAIL (`AttributeError: 'IngestedDocument' object has no attribute 'canonical'`, or `d.canonical` empty).

- [ ] **Step 3: Implement**
- In `ingested.py`, add `canonical: bytes = b""` as the last field of the frozen dataclass.
- In each loader, change the existing `IngestedDocument(document=..., text=...)` construction to also pass `canonical=canonical` (the `canonical` local already exists immediately above each `integrity_hash` line). Note: nvd/attack/kev build one `canonical` per document inside the loop; sigma likewise — pass the per-document `canonical`.

- [ ] **Step 4: Run to verify it passes**
Run: `./.venv/bin/pytest tests/test_loader_canonical.py -q` — Expected: PASS.
Then the full ingestion suite + lint/type: `./.venv/bin/pytest -q -k "nvd or attack or kev or sigma or loader" && ./.venv/bin/ruff check src tests && ./.venv/bin/mypy` — Expected: PASS/clean (no existing loader test broken by the new defaulted field).

- [ ] **Step 5: Commit**
```bash
git add src/secure_ai_research/ingestion tests/test_loader_canonical.py
git commit -m "feat(ingestion): loaders retain canonical bytes on IngestedDocument (Slice 3)"
```

---

### Task 3: `MinioObjectStore` adapter + `[minio]` extra + hermetic guards + integration

**Files:**
- Modify: `src/secure_ai_research/storage/objectstore.py` (add `MinioObjectStore`)
- Modify: `pyproject.toml` (optional extra)
- Test: `tests/test_minio_adapter.py` (hermetic), `tests/test_integration_minio.py` (`-m integration`)

**Interfaces:**
- Consumes: Task 1 — `ObjectStore` Protocol, `ObjectStoreError`.
- Produces: `MinioObjectStore(endpoint: str, access_key: str, secret_key: str, bucket: str, *, secure: bool = False)` implementing `ObjectStore`. `__init__` lazily imports `minio`, builds the client, and ensures the bucket. `put`/`get` map every backend fault to `ObjectStoreError` (type tag only). Object name = key with `:`→`/`.

- [ ] **Step 1: Write the failing hermetic tests** `tests/test_minio_adapter.py` (mirror `tests/test_pgvector_adapter.py`):

```python
def test_importing_objectstore_does_not_import_minio():
    if "minio" in sys.modules:
        pytest.skip("minio already loaded by another test in this process")
    sys.modules.pop("secure_ai_research.storage.objectstore", None)
    importlib.import_module("secure_ai_research.storage.objectstore")
    assert "minio" not in sys.modules

def test_missing_extra_raises_clear_object_store_error(monkeypatch):
    # force ImportError for minio; expect ObjectStoreError naming the extra
    ...
    with pytest.raises(ObjectStoreError) as exc:
        MinioObjectStore("localhost:9000", "k", "s", "sair-raw")
    assert "minio" in str(exc.value).lower()
```

- [ ] **Step 2: Run to verify they fail**
Run: `./.venv/bin/pytest tests/test_minio_adapter.py -q` — Expected: FAIL (cannot import `MinioObjectStore`).

- [ ] **Step 3: Implement `MinioObjectStore`** in `storage/objectstore.py`, mirroring `PgVectorStore`:
- `__init__`: `try: import minio; from minio import Minio except ImportError as exc: raise ObjectStoreError("minio extra not installed: pip install '.[minio]'") from exc`. Build `Minio(endpoint, access_key=..., secret_key=..., secure=secure)`; `_ensure_bucket()` → `if not client.bucket_exists(bucket): client.make_bucket(bucket)`, wrapping any fault as `ObjectStoreError(f"bucket init failed ({type(exc).__name__})")`.
- `_name(key)`: `key.replace(":", "/")`.
- `put`: `client.put_object(bucket, self._name(key), io.BytesIO(data), length=len(data))`, wrapping faults as `ObjectStoreError(f"put failed ({type(exc).__name__})")`.
- `get`: read the object via `client.get_object(...).read()`, wrapping faults as `ObjectStoreError(f"get failed ({type(exc).__name__})")`.

- [ ] **Step 4: Add the optional extra** to `pyproject.toml`: `[project.optional-dependencies]` → `minio = ["minio>=7.2,<8.0"]`.

- [ ] **Step 5: Write the integration tests** `tests/test_integration_minio.py` (`pytestmark = pytest.mark.integration`; `minio` imported only inside functions; `_require_minio()` importorskip + connect-or-skip). Cover: put→get round-trip returns identical bytes; `_ensure_bucket` creates then is idempotent on re-construct; `put` same key twice → `get` returns latest; bad endpoint → `ObjectStoreError`.

- [ ] **Step 6: Run**
Run: `./.venv/bin/pytest tests/test_minio_adapter.py -q` — Expected: PASS (2 hermetic).
Run: `./.venv/bin/ruff check src tests && ./.venv/bin/mypy` — Expected: clean.
Integration (manual, after `pip install -e '.[minio]'` + `docker compose up -d minio`): `./.venv/bin/pytest -q -m integration tests/test_integration_minio.py` — Expected: PASS.

- [ ] **Step 7: Commit**
```bash
git add src/secure_ai_research/storage/objectstore.py pyproject.toml tests/test_minio_adapter.py tests/test_integration_minio.py
git commit -m "feat(storage): real MinioObjectStore adapter behind the ObjectStore seam (Slice 3)"
```

---

### Task 4: Wire provenance end-to-end + fail-closed + factory/config/deps

**Files:**
- Create: `src/secure_ai_research/storage/factory.py`
- Modify: `src/secure_ai_research/config.py` (selector + bucket)
- Modify: `src/secure_ai_research/research_service.py` (constructor param; `put` in `_index_one`; `except ObjectStoreError` arm)
- Modify: `src/secure_ai_research/api/deps.py` (wire `make_object_store`)
- Modify: `ROADMAP.md`
- Test: `tests/test_object_store_factory.py`, `tests/test_provenance.py`

**Interfaces:**
- Consumes: Task 1 (`ObjectStore`, `ObjectStoreError`, `InMemoryObjectStore`), Task 2 (`IngestedDocument.canonical`), Task 3 (`MinioObjectStore` — referenced by the factory's lazy import, so it must already exist).
- Produces: `make_object_store(settings: Settings) -> ObjectStore`; `Settings.object_store: Literal["memory","minio"]`, `Settings.minio_bucket: str`; `ResearchService(..., *, object_store: ObjectStore | None = None)`.

- [ ] **Step 1: Write the failing tests.**

`tests/test_object_store_factory.py` (mirror `test_vector_store_factory.py`):
```python
def test_default_is_in_memory():
    assert isinstance(make_object_store(Settings()), InMemoryObjectStore)

def test_minio_selected_by_env(monkeypatch):
    monkeypatch.setenv("SAIR_OBJECT_STORE", "minio")
    # minio branch: without the extra installed, construction raises ObjectStoreError naming the extra
    with pytest.raises(ObjectStoreError):
        make_object_store(Settings())
```

`tests/test_provenance.py`:
```python
class _SpyStore:            # records put calls; get unused
    def __init__(self): self.puts = []
    def put(self, key, data): self.puts.append((key, data))
    def get(self, key): raise KeyError

def test_index_persists_canonical_keyed_by_hash():
    spy = _SpyStore()
    docs = nvd.load(_nvd_sample_bytes())
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit_path, object_store=spy)
    svc.index(docs)
    # every indexed doc's canonical is stored under its integrity_hash
    assert {k for k, _ in spy.puts} == {d.document.integrity_hash for d in docs}
    for k, data in spy.puts:
        assert hashlib.sha256(data).hexdigest() == k[len("sha256:"):]

def test_object_store_fault_on_live_fetch_is_fetch_error_one_record(tmp_path):
    # armed raising object store on fetch-on-miss re-index → FETCH_ERROR, "" , one audit record, no leak
    ...
    assert res.outcome is Outcome.FETCH_ERROR and res.answer == "" and len(_audit_lines(audit)) == 1

def test_default_path_result_unchanged_and_no_minio_import():
    # a cve/search result with the (default in-memory) object store wired is byte-identical; minio not imported
    ...
    assert "minio" not in sys.modules
```

- [ ] **Step 2: Run to verify they fail**
Run: `./.venv/bin/pytest tests/test_object_store_factory.py tests/test_provenance.py -q`
Expected: FAIL (`make_object_store` missing; `ResearchService` has no `object_store` kwarg; provenance not persisted).

- [ ] **Step 3: Implement.**
- `storage/factory.py`: `make_object_store(settings)` → `if settings.object_store == "minio": from secure_ai_research.storage.objectstore import MinioObjectStore; return MinioObjectStore(settings.minio_endpoint, settings.minio_access_key, settings.minio_secret_key, settings.minio_bucket); return InMemoryObjectStore()`.
- `config.py`: add `object_store: Literal["memory","minio"] = "memory"` and `minio_bucket: str = "sair-raw"`.
- `research_service.py`:
  - Import `ObjectStore`, `ObjectStoreError`, `InMemoryObjectStore` from `secure_ai_research.storage`.
  - Constructor: add keyword-only `object_store: ObjectStore | None = None`; `self._object_store = object_store or InMemoryObjectStore()`.
  - `_index_one`: insert `self._object_store.put(doc.integrity_hash, item.canonical)` BEFORE `self._store.upsert(...)` (provenance-first; `_docs` still published last).
  - In `research_cve`'s existing live-fetch wrap around `self._index_if_absent(fetched)`, add `except ObjectStoreError as exc:` as a sibling arm to `except VectorStoreError`, emitting one `_emit_terminal(rid, analyst_id, objective, now, f"fetch_error: retrieval failed ({type(exc).__name__})")` and returning `ResearchResult(Outcome.FETCH_ERROR, "", [], rid)`. (The broad arm already catches it; the typed arm is parity.)
- `api/deps.py`: `from secure_ai_research.storage.factory import make_object_store`; pass `object_store=make_object_store(settings)` to `ResearchService(...)`.
- `ROADMAP.md`: tick Week 5 "Object store (MinIO) for raw payloads" with an annotation that this is the write-side provenance sink; serving/verify deferred to the next slice.

- [ ] **Step 4: Run to verify they pass + full suite**
Run: `./.venv/bin/pytest tests/test_object_store_factory.py tests/test_provenance.py -q` — Expected: PASS.
Run: `./.venv/bin/pytest -q` — Expected: full hermetic suite PASS (no regression; existing ResearchService constructions unaffected by the optional param).
Run: `./.venv/bin/ruff check src tests && ./.venv/bin/mypy` — Expected: clean.

- [ ] **Step 5: Commit**
```bash
git add src/secure_ai_research/storage/factory.py src/secure_ai_research/config.py src/secure_ai_research/research_service.py src/secure_ai_research/api/deps.py ROADMAP.md tests/test_object_store_factory.py tests/test_provenance.py
git commit -m "feat(storage): wire provenance put at index, fail-closed on store fault, factory+config+deps (Slice 3)"
```

---

## Self-review notes

- **Spec coverage:** seam+Error+InMemory (T1), loader retention+hash integrity (T2), Minio adapter+extra+lazy guards+integration (T3), service persistence+fail-closed+factory+config+deps+ROADMAP (T4). All design §6 components mapped.
- **Type consistency:** `put(key:str,data:bytes)->None` / `get(key:str)->bytes` identical across Protocol, InMemory, Minio, spy. `canonical: bytes`. `make_object_store(Settings)->ObjectStore`. `object_store: ObjectStore | None`.
- **Interface ordering:** T4's factory lazy-imports `MinioObjectStore`, which T3 creates → T3 precedes T4 (no stub needed, unlike Slice 2).
- **Review Focus:** #1→T4 fault test; #2,#3→T3 hermetic guards; #4→T2 hash-integrity; #5→T4 default-unchanged. All five pinned to owning tasks.
- **Proportion:** four tasks, test names + signatures only (no full bodies); proportional to the design.
