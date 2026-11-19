# Fetch-on-miss on `/research/cve/{id}` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When live fetch is enabled, `GET /research/cve/{id}` answers a real CVE absent from the corpus by fetching it from NVD on a miss, caching and indexing it, and returning a cited report — while the default (fetch off) path stays byte-for-byte offline.

**Architecture:** Fetch-on-miss lives inside `ResearchService.research_cve`, triggered only in the already-post-authorization "scope empty" branch via an optional injected `fetch_missing` callable (None = today's pure offline service). A typed error taxonomy splits NVD "absent" (→404) from "unavailable" (→503). `api/deps` builds the callable only when `SAIR_ALLOW_LIVE_FETCH` is true.

**Tech Stack:** Python 3.12, stdlib only (`threading`), FastAPI, pydantic-settings, pytest.

**Spec:** `docs/superpowers/specs/2026-11-19-phase2-fetch-on-miss-endpoint-design.md`

## Global Constraints

- stdlib only (no new runtime deps); Python 3.12; ruff/black/mypy clean, line length 100.
- `nvd.load` stays the single response-validation gate; the `CveSource` port stays byte-typed.
- Host-pinned base URL, refused redirects, unredirected `apiKey` (prior slice) unchanged and must hold on this path.
- Settings via `SAIR_` env vars; secrets never logged; `SAIR_ALLOW_LIVE_FETCH` defaults `false` (default app + every unit test stay offline).
- Default test suite hermetic (`addopts = -m "not integration"`); any real-network test is `@pytest.mark.integration`, CI-excluded.
- Exactly one append-only audit record per request on every path.
- Attribution footer on every commit:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU
  ```

## Review Focus

1. **Setting OFF ⇒ no network reachable.** With `allow_live_fetch=false`, `deps` builds no source and `fetch_missing` is `None`; an unknown CVE returns 404 and nothing can call out. (Test: T3 `test_unknown_cve_without_fetch_is_404`.)
2. **Unauthorized caller triggers no fetch.** A DENIED role never reaches the fetch branch; the injected source is never touched. (Test: T2 `test_denied_role_never_fetches`.)
3. **`index()` publishes `_docs` only after the doc's chunks are upserted**, so a concurrent reader never sees a doc with zero chunks (no empty-OK + wrong audit record). Hard to pin deterministically — reviewer verifies ordering. (Partial test: T2 `test_index_if_absent_is_idempotent`.)
4. **Every fetch path leaves exactly one audit record**, including fetch-absent and fetch-error, and the attempted-fetch records are distinguishable from never-fetched ones. (Tests: T2 `test_*_emits_one_record`, `test_fetch_records_name_the_fetch`.)
5. **A transient NVD failure (HTTP error, URLError, read timeout, malformed body, corrupt cache file) becomes 503 — never 404 and never an unhandled 500.** (Tests: T1 `test_*_raises_cve_unavailable`, T3 `test_fetch_unavailable_is_503`.)

---

### Task 1: Error taxonomy — `CveNotFound` / `CveUnavailable`

**Files:**
- Modify: `src/secure_ai_research/ingestion/source.py` (add two exceptions)
- Modify: `src/secure_ai_research/ingestion/nvd_source.py` (`NvdApiSource.fetch_raw`, `CachingCveSource.fetch_raw` raise sites)
- Test: `tests/test_nvd_source.py`

**Interfaces:**
- Produces: `class CveNotFound(ValueError)`, `class CveUnavailable(ValueError)` in `ingestion/source.py`.
- Consumes: existing `nvd.load(raw: bytes) -> list[IngestedDocument]` (returns `[]` on empty `vulnerabilities`, raises on malformed), `CveSource`/`Opener` in the same module.

- [ ] **Step 1: Write failing tests** in `tests/test_nvd_source.py`:
  - `test_http_error_raises_cve_unavailable`: opener raises `HTTPError(500)` → `pytest.raises(CveUnavailable)`.
  - `test_read_timeout_raises_cve_unavailable`: opener raises `TimeoutError("timed out")` → `pytest.raises(CveUnavailable)` (a bare read timeout is not a `URLError`).
  - `test_caching_empty_feed_raises_cve_not_found`: inner returns `b'{"vulnerabilities": []}'` → `pytest.raises(CveNotFound, match="no usable record")`, nothing written.
  - `test_caching_malformed_raises_cve_unavailable`: inner returns `b'[]'` (top-level list → `nvd.load` fails non-`ValueError`) → `pytest.raises(CveUnavailable)`, nothing written.
  - Keep the existing `CveNotFound`/`CveUnavailable` subclass `ValueError`, so existing `test_rate_limit_status_gives_clear_error`, `test_network_error_gives_clear_error`, `test_api_key_never_appears_in_error`, `test_empty_vulnerabilities_fails_loud_and_writes_nothing`, `test_malformed_body_fails_loud_and_writes_nothing` still pass unchanged.
- [ ] **Step 2: Run the new tests, verify they fail** (`CveNotFound`/`CveUnavailable` undefined, or wrong type raised).
- [ ] **Step 3: Add the exceptions** to `ingestion/source.py`: `class CveNotFound(ValueError): ...` and `class CveUnavailable(ValueError): ...` (one-line docstrings: absent vs upstream-unavailable).
- [ ] **Step 4: Rewire `NvdApiSource.fetch_raw`** raise sites: catch `urllib.error.HTTPError` first (keep the 403/429 message and the `HTTP {exc.code}` message, now raised as `CveUnavailable`), then catch `OSError` (covers `URLError` — an `OSError` — and a bare `TimeoutError`) → `raise CveUnavailable(f"NVD fetch failed for {cve_id}: {exc}") from exc`. `apiKey` never interpolated into any message.
- [ ] **Step 5: Rewire `CachingCveSource.fetch_raw`**: wrap `nvd.load(raw)` so empty (`[]`) → `raise CveNotFound(f"NVD returned no usable record for {cve_id}")`; any `nvd.load` failure (catch broad `Exception`) → `raise CveUnavailable(...) from exc`. Nothing written in either case (unchanged order: validate before `mkdir`/write).
- [ ] **Step 6: Run `tests/test_nvd_source.py`, verify all pass.** Then `ruff check . && black --check . && mypy`.
- [ ] **Step 7: Commit** (`feat(ingestion): typed CveNotFound/CveUnavailable error taxonomy`).

---

### Task 2: `ResearchService` fetch-on-miss

**Files:**
- Modify: `src/secure_ai_research/research_service.py`
- Test: `tests/test_research_service.py`

**Interfaces:**
- Consumes: `CveNotFound`, `CveUnavailable` (Task 1); `nvd.load` is NOT called here — the service receives a `fetch_missing` callable that already returns loaded docs.
- Produces:
  - `Outcome.FETCH_ERROR = "fetch_error"`.
  - `ResearchService.__init__(self, embedder, store, authorize, audit_path, limit=5, *, fetch_missing: Callable[[str], list[IngestedDocument]] | None = None)`.
  - `research_cve(self, cve_id, *, role) -> ResearchResult` — signature unchanged; new FETCH_ERROR outcome possible.

- [ ] **Step 1: Write failing tests** in `tests/test_research_service.py` (reuse the file's existing fixture helpers for building a service over the sample corpus; use `audit.record.read_records(path)` to count records). A fake callable:
  ```python
  class _FakeFetch:
      def __init__(self, docs=None, exc=None): self.docs, self.exc, self.calls = docs, exc, 0
      def __call__(self, cve_id):
          self.calls += 1
          if self.exc: raise self.exc
          return self.docs
  ```
  Tests:
  - `test_fetch_on_miss_returns_cited_answer`: service built with `fetch_missing` returning the loaded docs for an un-indexed real id (load `tests/fixtures` or the packaged sample's bytes via `nvd.load`); result `OK`, a citation for that id, `read_records == 1`.
  - `test_fetch_absent_returns_not_found`: `fetch_missing` raises `CveNotFound` → `Outcome.NOT_FOUND`, `citations == []`, `read_records == 1`.
  - `test_fetch_unavailable_returns_fetch_error`: `fetch_missing` raises `CveUnavailable` → `Outcome.FETCH_ERROR`, `read_records == 1`.
  - `test_denied_role_never_fetches`: role not in allowlist, spy `fetch_missing` → `Outcome.DENIED` and `spy.calls == 0`.
  - `test_miss_without_fetch_missing_is_not_found`: `fetch_missing=None`, unknown id → `Outcome.NOT_FOUND`, `spy` absent.
  - `test_fetch_records_name_the_fetch`: the fetch-absent record's `conclusion` contains "live fetch" and the fetch-error record's contains "unavailable" — distinct from a never-fetched `test_miss_without_fetch_missing` record's "no corpus retrieved".
  - `test_index_if_absent_is_idempotent`: calling the fetch path twice for the same id (fetch returns the same docs) indexes once and does not raise; second call's result still `OK`.
- [ ] **Step 2: Run them, verify they fail** (`FETCH_ERROR`/`fetch_missing` undefined).
- [ ] **Step 3: Add `Outcome.FETCH_ERROR`** and the `fetch_missing` param + `self._lock = threading.Lock()` (`import threading`).
- [ ] **Step 4: Factor indexing under the lock.** Add private `_index_one(self, item: IngestedDocument) -> None` doing embed→`store.upsert`→**then** `self._docs[id] = doc` (publish last). `index()` keeps its fail-loud dup check and calls `_index_one` under `self._lock`. Add `_index_if_absent(self, docs: list[IngestedDocument]) -> None`: under `self._lock`, for each doc whose id is not already in `_docs`, call `_index_one`.
- [ ] **Step 5: Add the fetch-on-miss branch** in `research_cve`, inside the existing `if not scope:` block (which is already past the role-level DENIED gate): if `self._fetch_missing is not None and cve_id not in self._docs`, `try: docs = self._fetch_missing(cve_id)` except `CveNotFound`: emit terminal + return `NOT_FOUND` (conclusion "not_found: live fetch returned no record"); except `CveUnavailable`: emit terminal + return `FETCH_ERROR` (conclusion "fetch_error: NVD unavailable"); else `self._index_if_absent(docs)` and recompute `allowed`/`scope`. After the branch, `if not scope:` emit terminal `NOT_FOUND` (conclusion "not_found: no corpus retrieved") as today. The OK path falls through unchanged (one record).
- [ ] **Step 6: Change `_emit_terminal`** to accept the conclusion string: `_emit_terminal(self, rid, analyst_id, objective, now, conclusion: str)`, writing it into `ResearchRecord.conclusion`. Update the three call sites (DENIED → "denied: no corpus retrieved"; the two NOT_FOUND cases and FETCH_ERROR as above).
- [ ] **Step 7: Run `tests/test_research_service.py`, verify all pass** (incl. the file's existing tests). Then `ruff/black/mypy`.
- [ ] **Step 8: Commit** (`feat(research): fetch-on-miss in ResearchService (authz-first, one audit record)`).

---

### Task 3: wire into the live app — setting, deps, route

**Files:**
- Modify: `src/secure_ai_research/config.py` (add `allow_live_fetch`)
- Modify: `src/secure_ai_research/api/deps.py` (build `fetch_missing` closure when enabled)
- Modify: `src/secure_ai_research/api/routers/research.py` (map `FETCH_ERROR` → 503)
- Test: `tests/test_config.py`, `tests/test_api.py`

**Interfaces:**
- Consumes: `CveNotFound`/`CveUnavailable` (Task 1, raised by the closure's sources); `Outcome.FETCH_ERROR` + `fetch_missing` param (Task 2); existing `NvdApiSource`, `CachingCveSource`, `nvd.load`, `get_settings`.
- Produces: `Settings.allow_live_fetch: bool`; a `get_service` that passes `fetch_missing` when enabled.

- [ ] **Step 1: Write failing tests.**
  - `tests/test_config.py`: `test_settings_allow_live_fetch_default_false` (`Settings().allow_live_fetch is False`); `test_settings_allow_live_fetch_from_env` (`SAIR_ALLOW_LIVE_FETCH=true` → `True`).
  - `tests/test_api.py` (FastAPI `TestClient`, override `get_service` via `app.dependency_overrides` with a service wired to a `_FakeFetch`; authorized role header `X-Role: research_analyst`; audit to a tmp path):
    - `test_fetch_on_miss_is_200_with_citation`: fake returns docs for an unknown id → 200, body has a citation for it.
    - `test_fetch_absent_is_404`: fake raises `CveNotFound` → 404.
    - `test_fetch_unavailable_is_503`: fake raises `CveUnavailable` → 503, `detail` == "upstream source unavailable".
    - `test_unknown_cve_without_fetch_is_404`: service with `fetch_missing=None` → unknown id 404 (offline default).
    - `test_unauthorized_never_fetches`: bad role + spy fake → 403 and `spy.calls == 0`.
- [ ] **Step 2: Run them, verify they fail** (`allow_live_fetch` undefined; 503 branch missing).
- [ ] **Step 3: Add `allow_live_fetch: bool = False`** to `Settings` (env `SAIR_ALLOW_LIVE_FETCH`).
- [ ] **Step 4: Update `get_service`** in `deps.py`: after indexing the fixture, if `get_settings().allow_live_fetch`, build `caching = CachingCveSource(NvdApiSource(api_key=s.nvd_api_key, timeout=s.nvd_fetch_timeout), s.nvd_cache_dir)` and a module-level closure `def _fetch_missing(cve_id): return nvd.load(caching.fetch_raw(cve_id))` wrapped so **any** `nvd.load` failure on a cache-hit's bytes raises `CveUnavailable` (broad `except Exception`); pass `fetch_missing=_fetch_missing` to the service. When disabled, pass nothing (`fetch_missing=None`).
- [ ] **Step 5: Add the route branch** in `research.py`: `if res.outcome is Outcome.FETCH_ERROR: return JSONResponse(status_code=503, content={"detail": "upstream source unavailable", "research_id": res.research_id})`, placed with the other outcome branches (after OK, with DENIED/NOT_FOUND).
- [ ] **Step 6: Run `tests/test_config.py tests/test_api.py`, verify pass.** Then `ruff/black/mypy`.
- [ ] **Step 7: Commit** (`feat(api): opt-in fetch-on-miss on /research/cve/{id} (SAIR_ALLOW_LIVE_FETCH)`).

---

### Task 4: live endpoint integration test (CI-excluded)

**Files:**
- Modify: `tests/test_nvd_fetch_integration.py` (add one endpoint test)

**Interfaces:**
- Consumes: the wired app (Task 3), FastAPI `TestClient`, `Settings`/`get_settings`.

- [ ] **Step 1: Write the test**, `@pytest.mark.integration`:
  - `test_live_endpoint_fetches_real_cve(tmp_path, monkeypatch)`: set `SAIR_ALLOW_LIVE_FETCH=true`, `SAIR_NVD_CACHE_DIR=tmp_path/"cache"`, `SAIR_AUDIT_LOG_PATH=tmp_path/"audit.jsonl"`; `get_settings.cache_clear()` before and in `finally`; `get_service.cache_clear()` likewise; `TestClient(app).get("/research/cve/CVE-2021-44228", headers={"X-Role": "research_analyst"})`. Wrap the request; on a `ValueError`-class network failure bubbling up, `pytest.skip`. Assert status 200 and a citation for `CVE-2021-44228` in the body (or skip if NVD unreachable).
- [ ] **Step 2: Verify default suite excludes it and stays offline:** `pytest -q` green with the test deselected; `pytest -m integration --co -q` lists it.
- [ ] **Step 3: Lint/type** — `ruff/black/mypy` clean.
- [ ] **Step 4: Commit** (`test(api): CI-excluded live fetch-on-miss endpoint test`).

---

## Self-review notes

- **Spec coverage:** §6.1 setting → T3; §6.2/§6.3 service fetch-on-miss + `_index_if_absent` + `_emit_terminal` conclusion → T2; §6.4 error taxonomy → T1 (+ closure broad-wrap in T3 step 4); §6.5 `FETCH_ERROR` + 503 → T2 (outcome) + T3 (route); §6.6 deps closure → T3; §6.7 lock + publish-last → T2; §6.8 tests → T2/T3 hermetic + T4 integration. All §2 goals and §4 anti-goals mapped.
- **Type consistency:** `fetch_missing: Callable[[str], list[IngestedDocument]] | None` identical in T2 (param) and T3 (closure passed). `CveNotFound`/`CveUnavailable` defined T1, caught in T2 (service) and produced via sources in T3. `Outcome.FETCH_ERROR` defined T2, mapped T3. `_index_if_absent(docs)` / `_index_one(item)` defined and used only in T2.
- **Review Focus:** each of the 5 has a pinning test noted above (items 1,2,4,5 fully; item 3 partial + reviewer-verified ordering).
- **Proportion:** four tasks, bodies given only for the fake-fetch helper and the one route line; everything else is signatures + test names + assertions.
- **Builder confirmation folded in:** NVD returns 200+empty for an absent well-formed id (verified 2026-11-19), so "absent" is the empty-feed → `CveNotFound` path, no HTTP-404 special case (design §10.1).
