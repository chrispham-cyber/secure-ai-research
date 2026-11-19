# Phase 2 — Real NVD fetch slice (design)

> **Scope: PUBLIC data only.** Adds the project's **first outbound network call**, deliberately
> isolated: default/offline paths and all CI unit tests stay hermetic; the live fetch is opt-in and
> gated. No CUI/classified, no new runtime dependencies.

**Date:** 2026-11-19 · **Status:** proposed (awaiting approval) · **Implements:** ROADMAP Phase 2,
Week 5 ("Ingestion loaders: NVD … → `ResearchDocument` with content hashes"), narrow increment.

## 1. Intent & why

The prior slice built the retrieval spine against a committed **synthetic** NVD fixture and explicitly
deferred "a real fetch script" to the future. This slice closes that gap for NVD only: fetch a **real**
CVE from the NVD API 2.0, feed it through the *existing, unchanged* `nvd.load → ResearchService`
pipeline, and produce a cited answer end-to-end. The point is to prove the pipeline works on real,
messy public data (real descriptions contain brackets, long text, extra fields) **without weakening**
the offline/hermetic posture the whole repo depends on. It is the smallest real-data increment that
seeds the ROADMAP's "raw payload store" direction (an on-disk cache today; MinIO later, behind the same
port).

## 2. Goals

- A `CveSource` port with: a real `NvdApiSource` (stdlib `urllib`), a deterministic `FixtureCveSource`
  fake, and a `CachingCveSource` decorator (gitignored on-disk cache).
- A demo entrypoint (reusable function + `python -m …` CLI) that fetches one CVE → `nvd.load` →
  `ResearchService` → prints the cited answer.
- **Offline by default:** the FastAPI app and `deps.get_service` are unchanged (fixture-backed). The
  live fetch runs only when explicitly invoked (CLI or integration test).
- Hermetic unit tests of all fetch/cache logic (HTTP transport is injectable; no real network).
- Exactly **one** `@pytest.mark.integration` test that hits live NVD, excluded from CI
  (`pytest -m "not integration"`).

## 3. Non-goals (this slice)

- **No change to the HTTP endpoint or default corpus.** `GET /research/cve/{id}` stays fixture-backed
  and offline; wiring fetched CVEs into the live endpoint / cache-backed `get_service` is deferred.
- No MinIO, no pgvector, no other sources (KEV/ATT&CK/Sigma stay stubs).
- No full-corpus or incremental (`lastModStartDate`) sync — **single-CVE fetch only**. Batch/resumable
  sync is a later slice.
- No real Ollama/embeddings change (the deterministic `HashingEmbedder` still backs the demo).
- No new runtime dependency. No production authentication (X-Role unchanged).

## 4. Anti-goals (would make this a failure even if it "works")

- Any unit test or default/offline path making a network call.
- Committing fetched data, a cache file, or an API key; leaking the key to logs.
- Sending Chris's name/email to NVD (User-Agent or otherwise).
- Letting an untrusted NVD response or cache file bypass `nvd.load`'s fail-loud validation.
- Allowing `cve_id` to influence the request beyond the `cveId` query value (SSRF / arbitrary URL) or
  the cache filename (path traversal).

## 5. Constraints

- Python 3.12, **stdlib only** (`urllib.request`, `urllib.parse`, `pathlib`, `json`); ruff/black/mypy clean.
- Tests hermetic; network only behind the registered `integration` marker, which CI excludes.
- Secrets via env (`SAIR_NVD_API_KEY`), never committed/logged. Cache under `data/nvd-cache/`
  (`.gitignore` already blocks `data/`).
- `nvd.load` is the **single** validation gate for untrusted input (NVD response, cache bytes). The
  fetch/cache layer adds no independent/divergent validation. The cache may *call* `nvd.load` purely as
  a go/no-go persist gate (same gate reused — §7.4); `FixtureCveSource` reads **trusted, packaged**
  sample data, which is test scaffolding, not untrusted-input validation.

## 6. Approaches considered

- **A — Port + caching decorator + fail-safe default (CHOSEN).** `CveSource.fetch_raw(cve_id) -> bytes`
  (raw NVD 2.0 feed). `NvdApiSource` (real), `FixtureCveSource` (fake), `CachingCveSource` (decorator).
  Matches the established port+fake pattern; unit tests stay hermetic by injecting the HTTP transport;
  the on-disk cache is exactly where MinIO later swaps in behind the same port.
- **B — Direct adapter, no cache.** Thinner, but offline-by-default is weaker (every demo needs network)
  and it seeds nothing for the raw-payload-store direction. Rejected.
- **C — Fetch-to-cache CLI, no port; point `get_service` at the cache.** Simplest split, but the weakest
  test seam for fetch logic and it muddies the corpus (fixture + cache mixed into the live endpoint,
  breaking offline-by-default). Rejected.

## 7. The design (decided)

### 7.1 Port — `retrieval/ports.py` (or a new `ingestion/source.py`)
```python
class CveSource(Protocol):
    def fetch_raw(self, cve_id: str) -> bytes: ...   # raw NVD 2.0 feed JSON; nvd.load parses it
```
The NVD API 2.0 single-CVE response is already `{"vulnerabilities":[{"cve":{…}}]}`, i.e. exactly what
`nvd.load` consumes, so no new parsing is introduced anywhere.

### 7.2 `NvdApiSource` (real) — `ingestion/nvd_source.py`
- `__init__(self, *, api_key: str | None = None, base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0", timeout: float = 30.0, opener: Opener | None = None)` where
  `Opener = Callable[[urllib.request.Request, float], bytes]`; the default opener wraps
  `urllib.request.urlopen`. **`opener` is the injection seam for hermetic unit tests.**
- `fetch_raw(cve_id)`:
  1. Validate `cve_id` against `^CVE-\d{4}-\d{4,}$`; else `ValueError` (before any network).
  2. `url = base_url + "?" + urlencode({"cveId": cve_id})` — host is fixed; `cve_id` only fills the value.
  3. `Request(url, headers={"User-Agent": "secure-ai-research/0.1 (research tool)", **({"apiKey": api_key} if api_key else {})})`.
  4. `return self._opener(request, self._timeout)`.
  5. On `HTTPError` 403/429 → `ValueError("NVD rate limit / forbidden (set SAIR_NVD_API_KEY?)")`; other
     `URLError`/`HTTPError` → `ValueError(f"NVD fetch failed for {cve_id}: {exc}")`. Never logs `api_key`.

### 7.3 `FixtureCveSource` (fake) — in `tests/` (test double, not shipped in `src/`)
- Holds the packaged synthetic feed **bytes** and `fetch_raw(cve_id)` returns them **as-is** — no
  parsing, no subsetting (it stores bytes, so it needs no `json` at all; downstream `research_cve` does
  the per-id filtering). Deterministic, offline; backs the unit + offline end-to-end tests.

### 7.4 `CachingCveSource` (decorator) — `ingestion/nvd_source.py`
- `__init__(self, inner: CveSource, cache_dir: Path)`.
- `fetch_raw(cve_id)`: validate `cve_id` format (so the filename can't traverse); `path = cache_dir /
  f"{cve_id}.json"`; if it exists → `read_bytes()` and return (offline hit, `inner` not called); else
  `raw = inner.fetch_raw(cve_id)`, then **persist only a usable response**: if `nvd.load(raw)` returns
  no document (empty `vulnerabilities`) or raises (malformed), **do not write** and raise
  `ValueError(f"NVD returned no usable record for {cve_id}")` — so a 200-with-`[]` (e.g. an unpublished
  or rejected CVE) or a garbled body never poisons the cache into permanent `NOT_FOUND`; otherwise
  write atomically (temp file + `os.replace`) and return `raw`.
- The port still returns **bytes**; the `nvd.load` call here is the *same* single gate reused as a
  go/no-go, not a second validator. A cache **hit** is not re-validated (it passed the gate when
  written). **Deferred (non-goal this slice):** TTL / `--refresh` eviction and refresh-on-NVD-update —
  a stale or mistaken entry is cleared by deleting the file. When MinIO later replaces the on-disk
  store behind this port, the persist-gate moves to the composition layer.

### 7.5 Demo entrypoint — `ingestion/fetch_cve.py`
- `def research_from_source(cve_id, *, role, source: CveSource, audit_path: Path) -> ResearchResult`:
  `raw = source.fetch_raw(cve_id)` → `docs = nvd.load(raw)` → build a throwaway `ResearchService(
  HashingEmbedder(), InMemoryVectorStore(), authorize, audit_path)` → `index(docs)` →
  `return research_cve(cve_id, role=role)`.
- `__main__` CLI: `python -m secure_ai_research.ingestion.fetch_cve CVE-XXXX [--role research_analyst]`;
  builds `CachingCveSource(NvdApiSource(api_key=get_settings().nvd_api_key, timeout=get_settings().nvd_fetch_timeout), get_settings().nvd_cache_dir)`,
  calls `research_from_source`, prints outcome + answer, and exits non-zero on `DENIED`/`NOT_FOUND`
  (exact codes/formatting are builder detail, §10). Audit goes to the configured audit log — one trail
  shared with the app; records already self-identify (`data_source_ids=["NVD"]`, `research_id`,
  timestamp), so real and synthetic entries stay distinguishable without a separate path.

### 7.6 Config — `config.py`
Add to `Settings` (env prefix `SAIR_`, offline-safe defaults; nothing auto-fetches):
`nvd_api_key: str | None = None`, `nvd_cache_dir: Path = Path("data/nvd-cache")`,
`nvd_fetch_timeout: float = 30.0`. **No `nvd_api_base_url` setting** — the base URL is a pinned module
constant inside `NvdApiSource` (its `base_url` __init__ param exists only for test injection, never
read from env), so the host cannot be redirected via environment and `apiKey` can never be sent to an
attacker-chosen host (honors §4/§9 host-pinning).

### 7.7 Pytest marker
The `integration` marker is **already registered** in `pyproject.toml` and CI **already runs**
`-m "not integration"` (confirmed in builder check) — no config change needed; just apply the marker
to the new integration test.

## 8. Tests

**Hermetic (unit, in CI):**
- `NvdApiSource` with an injected fake opener: URL has `cveId=<id>` and the pinned host; User-Agent is
  the generic string (no email/name); `apiKey` header present iff key given; malformed `cve_id` →
  `ValueError` and opener **never called**; a fake `HTTPError(403)` → clear rate-limit `ValueError`.
- `CachingCveSource`: miss → delegates to a spy inner and writes the file; hit → serves from disk and
  the spy's call count is `0`; malformed `cve_id` → `ValueError`, no file touched; **inner returns an
  empty (`vulnerabilities: []`) or malformed body → `ValueError` and nothing is written** (no cache
  poisoning).
- `FixtureCveSource`: `fetch_raw` returns the stored packaged bytes, and `nvd.load` parses them into the
  expected docs.
- Offline end-to-end: `research_from_source(..., source=FixtureCveSource(...))` → `OK` with a citation
  whose `document_id` matches — proving the wiring with **no network**.

**Integration (NOT in CI), `@pytest.mark.integration`:**
- One test hitting live NVD for a well-known real CVE (e.g. `CVE-2021-44228`): `NvdApiSource.fetch_raw`
  returns parseable bytes; `nvd.load` yields a doc; `research_from_source` → `OK` with a citation.
  Skips (not fails) if NVD is unreachable/rate-limited.

## 9. Threat notes (STRIDE-ish, brief)

- **SSRF / tampering:** host is a **module constant** (not env-overridable), `cve_id` validated, only the `cveId` *value* is client-influenced → no arbitrary URL; `apiKey` can only ever reach NVD.
- **Untrusted response/cache (tampering):** returned as bytes, validated solely by `nvd.load`'s fail-loud parse.
- **Info disclosure:** generic User-Agent (no PII); `api_key` from env, never logged/committed.
- **Path traversal:** `cve_id` pattern has no separators; validated again in the cache decorator before building the path.
- **DoS/hang:** explicit request timeout.

## 10. Left to the builder

- Exact module placement (`ingestion/nvd_source.py` vs `ingestion/source.py`) and whether `CveSource`
  lives in `ports.py` or a new `ingestion/source.py` — builder's call, following existing layout.
- The precise default-opener wrapper around `urlopen` (reading `resp.read()`, mapping status).
- CLI arg parsing (stdlib `argparse`), exit codes, and output formatting.
- Which real CVE to pin in the integration test and the skip-on-unreachable mechanism.

## 11. Resolved in builder check (2026-11-19)

A fresh builder-check reviewer confirmed every integration claim (nvd.load shape, `ResearchService` /
`research_cve` signatures, `integration` marker + CI filter present, `data/` gitignored, `research_analyst`
allowed). Five gap questions were raised and settled as author calls — none changes *what* gets built (a
real CVE → cited answer), only internals:

1. **Cache poisoning / staleness** → the decorator persists only a response `nvd.load` accepts;
   empty/malformed → fail loud, nothing written (§7.4). TTL/refresh deferred (non-goal).
2. **Env-overridable base URL contradicted host-pinning** → dropped the `nvd_api_base_url` setting; the
   base URL is a pinned constant (§7.6, §9); the `nvd_fetch_timeout` setting is wired into the CLI.
3. **Fake vs. "never parses" + placement** → `FixtureCveSource` returns stored packaged bytes as-is (no
   parsing) and lives in `tests/` (§7.3).
4. **Valid-but-wrong / empty CVE** → empty fails loud (per #1); a mismatched id falls out as `NOT_FOUND`
   (not in scope), never a wrong answer; CLI exit codes are builder detail (§7.5, §10).
5. **Shared audit log** → the CLI writes the one configured audit trail; records self-identify, so no
   separate demo path (§7.5).
