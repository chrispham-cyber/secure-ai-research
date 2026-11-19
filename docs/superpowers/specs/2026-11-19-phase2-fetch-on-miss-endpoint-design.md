# Phase 2 — fetch-on-miss on the live `/research/cve/{id}` endpoint — design

**Date:** 2026-11-19
**Status:** draft (awaiting approval)
**Repo:** `secure-ai-research` (local git, no remote)
**Builds on:** the NVD retrieval slice (`main`@906d7aa) and the real-NVD-fetch slice (`main`@43a4399).

## 1. Intent and why

Today `GET /research/cve/{id}` answers only the two synthetic CVEs baked into the packaged
fixture (`nvd_sample.json`); every real CVE returns 404. The previous slice built the
machinery to fetch a real CVE from NVD (`NvdApiSource` → `CachingCveSource` → `nvd.load`)
and prove it end-to-end, but deliberately left the live FastAPI app offline and
fixture-backed. This slice connects the two: when a caller asks for a CVE the corpus does
not have, and live fetch is explicitly enabled, the endpoint fetches it from NVD, caches
it, indexes it, and answers with a cited report — so the API is useful for *real* CVEs,
not just the demo fixtures.

The platform's core posture is **offline-by-default**. Opening an outbound network call
from inside an HTTP handler is a real departure, so it is **opt-in and off by default**;
with the switch off (the default, and every unit test), the endpoint behaves exactly as it
does today and makes no network call.

## 2. Goals

- `GET /research/cve/{id}` answers a real CVE absent from the corpus by fetching it from
  NVD on a miss, **only when `SAIR_ALLOW_LIVE_FETCH=true`**.
- Reuse the existing fetch/cache machinery and the authorize-before-retrieve pipeline; the
  route's and `research_cve`'s external signatures are unchanged.
- **Authz-first:** a fetch is triggered only for a caller who has passed the role-level
  authorization check. An unauthorized caller gets today's response (403) and triggers no
  fetch.
- **Exactly one audit record per request**, on every path including the fetch path and the
  fetch-failure path.
- Distinguish **absent** (NVD has no such CVE → 404) from **unavailable** (NVD errored or
  timed out → 503).

## 3. Non-goals (explicitly out of scope — do not build)

- Live fetch on by default. The setting defaults to `false`; nothing auto-fetches.
- Cache TTL / refresh / eviction / staleness handling (deferred, as in the fetch slice).
- A separate prefetch/batch/admin endpoint; `/research/attack` and `/research/search`
  stay 501.
- Real authentication. `X-Role` remains the Phase-1 self-asserted **stub** (threat T1);
  OIDC is Phase 5. Because a network-triggering path is now behind that stub, the route
  still must **not be exposed on a real network** until Phase 5.
- Multi-worker/multi-process safety: a cross-process shared cache, or correctness under a
  multi-worker server. Single-worker dev assumption (see §6.7).
- Retry / backoff / rate-limit handling against NVD. A failure fails loud (503).
- Unbounded-growth mitigation for the in-memory corpus (fetched CVEs accumulate for the
  process lifetime; acceptable for a dev stub).

## 4. Anti-goals (failure even if it "works")

- The default/offline path (setting off, or any unit test) making **any** network call.
- An **unauthorized** caller triggering an outbound fetch (amplification) or being able to
  distinguish "exists but forbidden" from "absent".
- A fetched-but-empty or garbled response **poisoning** the on-disk cache or the in-memory
  corpus (→ permanent wrong answer / NOT_FOUND).
- `apiKey` leaking into a log, an error, or off the pinned host on this path (the prior
  slice's invariant must stay true here).
- More than one audit record per request, or a live fetch that leaves no audit trail.

## 5. Constraints

- stdlib only (no new runtime deps); Python 3.12; ruff/black/mypy clean, line length 100.
- `nvd.load` stays the single response-validation gate; the `CveSource` port stays
  byte-typed.
- Host-pinned base URL, refused redirects, and unredirected `apiKey` (from the fetch
  slice) are unchanged and must hold on this path.
- Settings via `SAIR_` env vars; secrets never logged.
- Default test suite hermetic (`addopts = -m "not integration"`); any real network test is
  `@pytest.mark.integration`, CI-excluded.
- Attribution footer on every commit.

## 6. Design (the decided "how")

### 6.1 Opt-in setting
`Settings` gains `allow_live_fetch: bool = False` (env `SAIR_ALLOW_LIVE_FETCH`). Off is the
default and keeps the app offline. It is read only in `api/deps.get_service`.

### 6.2 Approach (chosen): fetch-on-miss inside `ResearchService`
`ResearchService.__init__` gains one optional parameter:

```
fetch_missing: Callable[[str], list[IngestedDocument]] | None = None
```

When `None` (the default — today's app and every unit test unless told otherwise) the
service is byte-for-byte today's behavior: pure, deterministic, offline. The parameter is
a **callable that returns loaded documents or raises** (§6.4), not a `CveSource`, so the
service stays unaware of NVD/urllib specifics and is trivial to fake in tests.

### 6.3 `research_cve` flow (the only method that changes)
Unchanged up to and including the role-level `DENIED` check (so **authz runs first**). The
change is at the existing "scope is empty" branch (today an immediate `NOT_FOUND`):

```
if not scope:
    # Only an authorized caller reaches here (past the DENIED gate). Fetch only when
    # enabled AND the CVE is genuinely absent from the corpus (never when it is present
    # but unauthorized — that must stay NOT_FOUND, no fetch, no leak).
    if fetch_missing is not None and cve_id not in self._docs:
        try:
            docs = fetch_missing(cve_id)          # may raise CveNotFound / CveUnavailable
        except CveNotFound:
            -> emit NOT_FOUND terminal record; return NOT_FOUND          # 404 (absent)
        except CveUnavailable:
            -> emit FETCH_ERROR terminal record; return FETCH_ERROR      # 503 (upstream)
        # fetch ran outside the lock; index under the lock, re-checking first so a
        # concurrent double-fetch indexes the doc only once (see §6.7).
        self._index_if_absent(cve_id, docs)
        # recompute allowed/scope now that the corpus has the fetched doc
        allowed = {did for did, doc in self._docs.items() if self._authorize(role, doc)}
        scope = allowed & {cve_id}
    if not scope:
        -> emit NOT_FOUND terminal record; return NOT_FOUND
# fall through to the existing retrieval + single OK record
```

The happy fetch path then flows into the **existing** retrieval-and-emit code, so there is
exactly **one** audit record for the request. That record already self-identifies a live
fetch: a fetched NVD document carries `source = "NVD"`, so `data_source_ids` on the record
is `["NVD"]`. (No new audit-schema field; provenance is already captured.)

### 6.4 Error taxonomy: absent vs unavailable
Two exceptions are added next to the port, in `ingestion/source.py`, both subclassing
`ValueError` (so existing `except ValueError` callers and the fetch-slice tests that match
on message substrings are unaffected):

- `CveNotFound(ValueError)` — NVD returned a usable response with **no** record for the id
  (the 200-with-`[]` case). Means "absent" → 404.
- `CveUnavailable(ValueError)` — the fetch could not be completed or the body was
  unusable: HTTP error, network/DNS error, timeout, or a malformed body `nvd.load`
  rejects. Means "upstream problem" → 503.

Mapping moves into the existing raise sites, broadened so **no** fetch path can yield an
unhandled 500 / no audit record (the only exceptions escaping the fetch callable are
`CveNotFound` and `CveUnavailable`):
- `NvdApiSource.fetch_raw`: any `OSError` → `CveUnavailable`. `OSError` covers `URLError`
  (it subclasses `OSError`) and a bare `TimeoutError` raised from `resp.read()` after the
  connection opens; the 403/429 clear message is kept. (Same messages, so
  `test_rate_limit_status_gives_clear_error` / `test_network_error_gives_clear_error` /
  `test_api_key_never_appears_in_error` still pass.)
- `CachingCveSource.fetch_raw`: empty feed (`nvd.load` returns `[]`) → `CveNotFound`
  (message still contains "no usable record"); **any** `nvd.load` failure — a `ValueError`
  or a non-`ValueError` such as `AttributeError` on a top-level JSON list — → `CveUnavailable`.
  Nothing is cached in either case (unchanged).
- The `deps` closure passes a cache **hit**'s bytes through `nvd.load` as well, so a
  corrupt cache file yields `CveUnavailable` (503), never an unhandled 500. Evicting a
  corrupt file is deferred: atomic post-validation writes mean it can only arise from
  external tampering.

### 6.5 New outcome + route mapping
`Outcome` gains `FETCH_ERROR = "fetch_error"`. The router adds one branch:
`FETCH_ERROR → 503 {"detail": "upstream source unavailable", "research_id": ...}`. The
existing OK/DENIED/NOT_FOUND → 200/403/404 branches are unchanged. 422 (malformed id by
`Path` pattern) still precedes everything.

### 6.6 Wiring in `api/deps.get_service`
`get_service` indexes the fixture exactly as today. Additionally, when
`settings.allow_live_fetch` is true, it builds the fetch callable and passes it to the
service:

```
fetch_missing = None
if settings.allow_live_fetch:
    caching = CachingCveSource(
        NvdApiSource(api_key=settings.nvd_api_key, timeout=settings.nvd_fetch_timeout),
        settings.nvd_cache_dir,
    )
    def fetch_missing(cve_id):           # closure; returns docs or raises Cve*
        return nvd.load(caching.fetch_raw(cve_id))
```

A CVE already on disk is served by `CachingCveSource` **without a network call** (cache
hit); the setting gates the whole path, so with it off even a cached CVE returns 404 —
"off" means fixture-only, fully offline. The API path reuses `nvd_fetch_timeout` (one
knob) as its request-blocking timeout; operators lower it if a 30 s worst-case hang
matters.

### 6.7 Concurrency (single-process, threadpool)
FastAPI runs sync routes in a worker threadpool, so concurrent `research_cve` calls are
real even with one uvicorn worker. Two corrections (the earlier "no lock" stance was
unsafe):
- **`index()` publishes `self._docs[id]` *after* embedding and upserting that doc's
  chunks** (not before). A concurrent reader therefore never sees a doc in `_docs` whose
  chunks are not yet queryable — closing the "empty OK with a wrong audit record" race.
- **A `threading.Lock` guards the in-memory index step**, while the network fetch runs
  *outside* the lock (no long holds, no head-of-line blocking on a slow fetch). Under the
  lock the fetch path re-checks `cve_id in self._docs` and indexes only if still absent
  (`_index_if_absent`), so a double-fetch of the same CVE (two threads both missing)
  indexes exactly once — no duplicate chunks — and `index()`'s fail-loud dup guard stays
  for the explicit/startup path. Cross-process coordination and a shared cache remain
  non-goals.

### 6.8 Tests
- **Service unit tests (hermetic, injected fake `fetch_missing`):** OK+citation when the
  fake returns docs; `NOT_FOUND` when it raises `CveNotFound`; `FETCH_ERROR` when it raises
  `CveUnavailable`; **DENIED path never calls the fake** (unauthorized → no fetch);
  `NOT_FOUND` with fetch disabled (`fetch_missing=None`); exactly one audit record (one
  JSONL line) on each of those paths.
- **Error-taxonomy tests** (`test_nvd_source.py`): `NvdApiSource` raises `CveUnavailable`;
  `CachingCveSource` raises `CveNotFound` on empty and `CveUnavailable` on malformed;
  nothing cached in either.
- **Route tests** (`TestClient`, `get_service` overridden with a service wired to a fake
  `fetch_missing`): 200 / 403 / 404 / 503 mapping; unknown CVE with fetch disabled → 404.
- **Settings test:** `allow_live_fetch` defaults false; `SAIR_ALLOW_LIVE_FETCH=true`
  parsed.
- **One CI-excluded integration test** (`@pytest.mark.integration`): live endpoint with
  fetch enabled answers a real CVE (e.g. CVE-2021-44228) with a citation; keyless;
  skip-on-unreachable.
- The default suite stays green **without** a network call (setting off everywhere unit).

## 7. Approaches considered

- **Chosen — fetch-on-miss inside `ResearchService` (optional `fetch_missing` callable).**
  Keeps "authz before fetch" and "one audit record per request" in one place and trivially
  true (the fetch is inline in the single `research_cve` call); preserves the service's
  offline purity whenever no callable is injected (default app + tests). Cost: the service
  becomes network-*capable* when a callable is injected.
- **Rejected — orchestrator/wrapper around a pure `ResearchService`.** Isolates the network
  concern but calls `research_cve` twice on a miss → two audit records per request (breaks
  the one-record invariant) unless a lower-level hook is added, and splits the
  authz/fetch ordering across two components.
- **Rejected — cache-only / prefetch (offline read path).** The user explicitly chose
  fetch-on-miss over a cache-only or separate-prefetch posture.

## 8. Review focus (for the plan's Review Focus section)

1. Unauthorized caller (DENIED) triggers **no** fetch — the fake `fetch_missing` is never
   called; response identical to today.
2. Empty NVD feed → 404, and **nothing** written to cache or corpus (no poison).
3. Malformed/garbled NVD body → 503, nothing cached/indexed.
4. NVD network error/timeout → 503, **not** 404 (a transient failure must not masquerade as
   "absent").
5. Exactly one audit record per request on the fetch-OK, fetch-absent, and fetch-error
   paths.
6. Concurrent fetch of the same absent CVE does not crash (index race tolerated).
7. `apiKey` still never logged and never leaves the pinned host on this path.

## 9. What is left to the builder
Exact test names and assertions; the precise form of `_index_tolerating_races`; the closure
in `deps`; docstring wording. All interfaces and the control flow are fixed above.

## 10. Builder-check resolutions
A fresh builder-check (sonnet subagent) raised four questions; all were author calls (none
needed the owner's unique input).

1. **NVD status for an absent CVE — verified, design stands.** Probed NVD 2.0 (2026-11-19)
   with the well-formed nonexistent ids `CVE-2000-99999` and `CVE-1999-99998`: both return
   **HTTP 200, `totalResults: 0`, `vulnerabilities: []`**. So "absent" is the empty-feed
   path → `CveNotFound` → 404; no HTTP-404 special case is needed, and mapping every HTTP
   error to `CveUnavailable` (503) is correct — a 404 from NVD would be a genuine transport
   anomaly, not "absent". §6.4 unchanged by this.
2. **Every fetch failure → `CveUnavailable` (503) + one audit record** — §6.4 tightened to
   catch `OSError` (incl. `URLError` and a bare read `TimeoutError`) and any `nvd.load`
   failure (incl. non-`ValueError`), and a corrupt **cache-hit** file maps the same way, so
   no fetch path yields an unhandled 500 / no audit.
3. **Failed fetches are auditably distinct from never-attempted** — §6.3; anti-goal §4.
   `_emit_terminal` carries the conclusion text: a fetch-absent record reads "live fetch
   returned no record", a fetch-error record reads "NVD unavailable", vs. a never-fetched
   "no corpus retrieved". Every outbound attempt leaves a distinct trail.
4. **Concurrency races fixed** — §6.7 revised: `index()` publishes `_docs` after the
   chunks (no empty-OK), and a `threading.Lock` + in-lock re-check makes a double-fetch
   index once (no duplicate chunks). The earlier "no lock" stance is dropped.
