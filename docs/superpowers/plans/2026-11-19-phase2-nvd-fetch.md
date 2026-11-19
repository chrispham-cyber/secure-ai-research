# Phase 2 — Real NVD fetch slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fetch one real CVE from the NVD API 2.0 and run it through the existing `nvd.load → ResearchService` pipeline to a cited answer, without weakening the repo's offline/hermetic posture.

**Architecture:** A `CveSource` port with three implementations — `NvdApiSource` (real, stdlib `urllib`, injectable HTTP transport), `CachingCveSource` (read/write-through on-disk cache that persists only responses `nvd.load` accepts), and `FixtureCveSource` (test double). A reusable `research_from_source()` + a `python -m` CLI wire them to the existing service. The default FastAPI app and all CI unit tests stay offline; the one live test is `@pytest.mark.integration` (CI-excluded).

**Tech Stack:** Python 3.12, stdlib only (`urllib.request`, `urllib.parse`, `pathlib`, `json`, `re`, `argparse`), pytest. No new runtime dependency.

**Spec:** `docs/superpowers/specs/2026-11-19-phase2-nvd-fetch-design.md`

## Global Constraints

- **stdlib only** — no new runtime dependency. Python 3.12.
- **ruff + black + mypy clean**, line length 100; mypy checks `src` only.
- **Tests hermetic.** Network only behind `@pytest.mark.integration`, which is already registered in `pyproject.toml` and already excluded by CI (`pytest -m "not integration"`). No unit/default path makes a network call.
- **Single validation gate:** untrusted bytes (NVD response, cache file) are validated only by `nvd.load`. The cache may *call* `nvd.load` as a go/no-go persist gate (same gate reused), never a second/divergent validator.
- **Host pinned:** base URL is a module constant `NVD_CVE_API` in `nvd_source.py`; `NvdApiSource.base_url` is a constructor param for test injection only, never read from env. `apiKey` can only ever reach NVD.
- **`cve_id` validated** against `^CVE-\d{4}-\d{4,}$` before any network call and before building any cache path (no SSRF, no path traversal).
- **Secrets via env** (`SAIR_NVD_API_KEY`), never committed, never placed in a log or error message. Cache under `data/nvd-cache/` (already gitignored).
- **Generic User-Agent** `secure-ai-research/0.1 (research tool)` — no name/email/PII.
- **Every commit** ends with the attribution footer:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU
  ```

## Review Focus

- **NVD 200 with empty `vulnerabilities: []`** (CVE not yet published / rejected): must fail loud and NOT write the cache, or the entry poisons every later hit into permanent `NOT_FOUND`. → Task 2.
- **Truncated / garbled NVD body:** `nvd.load` raises; the cache must not persist it. → Task 2.
- **Requested CVE id not in the returned feed:** the research path yields `NOT_FOUND`, never a citation for a different CVE. → Task 3.
- **`api_key` value must never appear** in an error message or log when a fetch fails. → Task 1.
- **Malformed `cve_id`** (`"../etc"`, `"CVE-x"`, `"CVE-2021-"`): rejected before any network call (Task 1) and before building a cache path (Task 2).

---

## File Structure

- `src/secure_ai_research/ingestion/source.py` — **new.** `CveSource` Protocol + `Opener` type alias.
- `src/secure_ai_research/ingestion/nvd_source.py` — **new.** `NvdApiSource`, `CachingCveSource`, module constant `NVD_CVE_API`.
- `src/secure_ai_research/ingestion/fetch_cve.py` — **new.** `research_from_source()` + `main()` CLI.
- `src/secure_ai_research/config.py` — **modify.** Add 3 `Settings` fields.
- `tests/test_nvd_source.py` — **new.** Hermetic adapter + cache tests. Holds `FixtureCveSource`.
- `tests/test_fetch_cve.py` — **new.** Offline end-to-end + CLI tests.
- `tests/test_config.py` — **modify.** Defaults + env override for the new fields.
- `tests/test_nvd_fetch_integration.py` — **new.** One `@pytest.mark.integration` live test.

---

## Task 1: `CveSource` port + `NvdApiSource`

**Files:**
- Create: `src/secure_ai_research/ingestion/source.py`
- Create: `src/secure_ai_research/ingestion/nvd_source.py`
- Test: `tests/test_nvd_source.py`

**Interfaces:**
- Consumes: nothing from earlier tasks. (`urllib.request.Request`, `urllib.error.HTTPError`/`URLError`.)
- Produces:
  - `source.py`: `Opener = Callable[[urllib.request.Request, float], bytes]`; `class CveSource(Protocol): def fetch_raw(self, cve_id: str) -> bytes: ...`
  - `nvd_source.py`: `NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"`; `class NvdApiSource` with `__init__(self, *, api_key: str | None = None, base_url: str = NVD_CVE_API, timeout: float = 30.0, opener: Opener | None = None) -> None` and `def fetch_raw(self, cve_id: str) -> bytes`.

- [ ] **Step 1: Write failing tests** in `tests/test_nvd_source.py`. Use a fake opener that captures the `Request` and returns fixture bytes; for failures, one that raises.

```python
def test_fetch_builds_pinned_url_and_generic_ua():
    seen = {}
    def opener(req, timeout):
        seen["url"] = req.full_url
        seen["ua"] = req.get_header("User-agent")      # urllib Title-cases header keys
        seen["apikey"] = req.get_header("Apikey")
        return b'{"vulnerabilities":[]}'
    NvdApiSource(opener=opener).fetch_raw("CVE-2021-44228")
    assert seen["url"].startswith("https://services.nvd.nist.gov/rest/json/cves/2.0?")
    assert "cveId=CVE-2021-44228" in seen["url"]
    assert seen["ua"] == "secure-ai-research/0.1 (research tool)"
    assert seen["apikey"] is None                       # no key configured

def test_api_key_is_sent_when_configured():
    seen = {}
    def opener(req, timeout):
        seen["apikey"] = req.get_header("Apikey")
        return b"{}"
    NvdApiSource(api_key="k-123", opener=opener).fetch_raw("CVE-2021-44228")
    assert seen["apikey"] == "k-123"

def test_malformed_cve_id_rejected_before_network():
    calls = []
    def opener(req, timeout):
        calls.append(req); return b"{}"
    for bad in ["../etc/passwd", "CVE-x", "CVE-2021-", "nonsense"]:
        with pytest.raises(ValueError):
            NvdApiSource(opener=opener).fetch_raw(bad)
    assert calls == []                                  # opener never reached

def test_rate_limit_status_gives_clear_error():
    def opener(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, None)
    with pytest.raises(ValueError, match="rate limit|forbidden"):
        NvdApiSource(opener=opener).fetch_raw("CVE-2021-44228")

def test_api_key_never_appears_in_error():
    def opener(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, None)
    with pytest.raises(ValueError) as exc:
        NvdApiSource(api_key="SECRET-KEY", opener=opener).fetch_raw("CVE-2021-44228")
    assert "SECRET-KEY" not in str(exc.value)

def test_network_error_gives_clear_error():
    def opener(req, timeout):
        raise urllib.error.URLError("dns down")
    with pytest.raises(ValueError, match="CVE-2021-44228"):
        NvdApiSource(opener=opener).fetch_raw("CVE-2021-44228")
```

- [ ] **Step 2: Run, verify they fail** — `.venv/bin/python -m pytest tests/test_nvd_source.py -q`. Expected: FAIL (module/class not defined).
- [ ] **Step 3: Implement `source.py`** — the `Opener` alias and `CveSource` Protocol exactly as in Interfaces.
- [ ] **Step 4: Implement `NvdApiSource` in `nvd_source.py`.** Module-level `_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")`. Default opener wraps `urllib.request.urlopen(request, timeout=timeout)` and returns `resp.read()`. `fetch_raw`: validate id (else `ValueError`); `url = f"{self._base_url}?" + urllib.parse.urlencode({"cveId": cve_id})`; build `Request` with the generic `User-Agent` and `apiKey` header only when `api_key` is set; call opener. Catch `HTTPError` **before** `URLError` (subclass); map 403/429 → `ValueError("NVD rate limit / forbidden (set SAIR_NVD_API_KEY?)")`, other → `ValueError(f"NVD fetch failed for {cve_id}: {exc}")`. Never interpolate `api_key` into any message.
- [ ] **Step 5: Run, verify pass** — `.venv/bin/python -m pytest tests/test_nvd_source.py -q`. Expected: PASS.
- [ ] **Step 6: Lint/type** — `.venv/bin/ruff check . && .venv/bin/black --check . && .venv/bin/mypy`. Expected: clean.
- [ ] **Step 7: Commit** (`feat(ingestion): add CveSource port + NvdApiSource (stdlib, host-pinned)`), with the attribution footer.

---

## Task 2: `CachingCveSource`

**Files:**
- Modify: `src/secure_ai_research/ingestion/nvd_source.py`
- Test: `tests/test_nvd_source.py`

**Interfaces:**
- Consumes: `CveSource` (Task 1); `secure_ai_research.ingestion.nvd.load` (existing: `load(raw: bytes) -> list[IngestedDocument]`, returns `[]` for empty `vulnerabilities`, raises `ValueError` on malformed). A packaged valid feed at `secure_ai_research.ingestion/samples/nvd_sample.json`.
- Produces: `class CachingCveSource` with `__init__(self, inner: CveSource, cache_dir: Path) -> None` and `def fetch_raw(self, cve_id: str) -> bytes`.

- [ ] **Step 1: Write failing tests.** A spy inner records calls and returns given bytes.

```python
VALID = files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()

class _Spy:
    def __init__(self, raw): self.raw = raw; self.calls = 0
    def fetch_raw(self, cve_id): self.calls += 1; return self.raw

def test_miss_delegates_and_writes(tmp_path):
    spy = _Spy(VALID)
    out = CachingCveSource(spy, tmp_path).fetch_raw("CVE-2099-0001")
    assert out == VALID and spy.calls == 1
    assert (tmp_path / "CVE-2099-0001.json").read_bytes() == VALID

def test_hit_serves_from_disk_without_inner(tmp_path):
    (tmp_path / "CVE-2099-0001.json").write_bytes(VALID)
    spy = _Spy(b"should-not-be-used")
    out = CachingCveSource(spy, tmp_path).fetch_raw("CVE-2099-0001")
    assert out == VALID and spy.calls == 0

def test_empty_vulnerabilities_fails_loud_and_writes_nothing(tmp_path):
    spy = _Spy(b'{"vulnerabilities": []}')
    with pytest.raises(ValueError, match="no usable record"):
        CachingCveSource(spy, tmp_path).fetch_raw("CVE-2099-0001")
    assert not (tmp_path / "CVE-2099-0001.json").exists()

def test_malformed_body_fails_loud_and_writes_nothing(tmp_path):
    spy = _Spy(b"{ this is not json")
    with pytest.raises(ValueError):
        CachingCveSource(spy, tmp_path).fetch_raw("CVE-2099-0001")
    assert not (tmp_path / "CVE-2099-0001.json").exists()

def test_malformed_cve_id_rejected_before_path(tmp_path):
    spy = _Spy(VALID)
    with pytest.raises(ValueError):
        CachingCveSource(spy, tmp_path).fetch_raw("../escape")
    assert spy.calls == 0 and list(tmp_path.iterdir()) == []
```

- [ ] **Step 2: Run, verify fail** — `.venv/bin/python -m pytest tests/test_nvd_source.py -q`. Expected: FAIL (`CachingCveSource` not defined).
- [ ] **Step 3: Implement `CachingCveSource`.** Validate `cve_id` with the shared `_CVE_ID` (reuse Task 1's). On hit, `path.read_bytes()`. On miss: `raw = self._inner.fetch_raw(cve_id)`; call `nvd.load(raw)` — if it raises, let it propagate; if it returns an empty list, `raise ValueError(f"NVD returned no usable record for {cve_id}")`; otherwise write atomically (write to `path.with_suffix(".json.tmp")`, then `os.replace`) and return `raw`. Create `cache_dir` if missing (`mkdir(parents=True, exist_ok=True)`).
- [ ] **Step 4: Run, verify pass** — `.venv/bin/python -m pytest tests/test_nvd_source.py -q`. Expected: PASS.
- [ ] **Step 5: Lint/type** — ruff + black + mypy. Expected: clean.
- [ ] **Step 6: Commit** (`feat(ingestion): add CachingCveSource with nvd.load persist-gate`), with footer.

---

## Task 3: `research_from_source` + `FixtureCveSource` + offline end-to-end

**Files:**
- Create: `src/secure_ai_research/ingestion/fetch_cve.py`
- Test: `tests/test_fetch_cve.py`

**Interfaces:**
- Consumes: `CveSource` (Task 1); `nvd.load`; `ResearchService(embedder, store, authorize, audit_path)`, `.index(docs)`, `.research_cve(cve_id, *, role) -> ResearchResult` (with `.outcome`, `.citations`, `.answer`); `Outcome` enum; `HashingEmbedder`, `InMemoryVectorStore`, `authorize`.
- Produces: `def research_from_source(cve_id: str, *, role: str, source: CveSource, audit_path: Path) -> ResearchResult`.

- [ ] **Step 1: Write failing tests** in `tests/test_fetch_cve.py`. Define the test double here:

```python
VALID = files("secure_ai_research.ingestion").joinpath("samples", "nvd_sample.json").read_bytes()

class FixtureCveSource:                       # test double; returns packaged bytes as-is
    def __init__(self, raw: bytes = VALID): self._raw = raw
    def fetch_raw(self, cve_id: str) -> bytes: return self._raw

def test_offline_end_to_end_cited_answer(tmp_path):
    res = research_from_source(
        "CVE-2099-0001", role="research_analyst",
        source=FixtureCveSource(), audit_path=tmp_path / "audit.jsonl")
    assert res.outcome is Outcome.OK
    assert any(c.document_id == "CVE-2099-0001" for c in res.citations)

def test_requested_id_absent_from_feed_is_not_found(tmp_path):
    res = research_from_source(
        "CVE-2099-9999", role="research_analyst",       # not in the 2-CVE fixture
        source=FixtureCveSource(), audit_path=tmp_path / "audit.jsonl")
    assert res.outcome is Outcome.NOT_FOUND
    assert res.citations == []
```

- [ ] **Step 2: Run, verify fail** — `.venv/bin/python -m pytest tests/test_fetch_cve.py -q`. Expected: FAIL (`research_from_source` not defined).
- [ ] **Step 3: Implement `research_from_source`.** `svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit_path)`; `svc.index(nvd.load(source.fetch_raw(cve_id)))`; `return svc.research_cve(cve_id, role=role)`.
- [ ] **Step 4: Run, verify pass** — Expected: PASS.
- [ ] **Step 5: Lint/type** — ruff + black + mypy. Expected: clean.
- [ ] **Step 6: Commit** (`feat(ingestion): add research_from_source demo function`), with footer.

---

## Task 4: config settings + `main()` CLI

**Files:**
- Modify: `src/secure_ai_research/config.py`
- Modify: `src/secure_ai_research/ingestion/fetch_cve.py`
- Test: `tests/test_config.py`, `tests/test_fetch_cve.py`

**Interfaces:**
- Consumes: `research_from_source` (Task 3); `NvdApiSource`, `CachingCveSource` (Tasks 1–2); `get_settings()` (existing, with new fields + existing `audit_log_path`); `Outcome`.
- Produces: `Settings` fields `nvd_api_key: str | None = None`, `nvd_cache_dir: Path = Path("data/nvd-cache")`, `nvd_fetch_timeout: float = 30.0`; `def main(argv: list[str] | None = None, *, source: CveSource | None = None) -> int`.

- [ ] **Step 1: Write failing tests.** Config (in `test_config.py`): defaults for the three fields; `SAIR_NVD_API_KEY` env → `nvd_api_key`. CLI (in `test_fetch_cve.py`) injects a source to stay hermetic:

```python
def test_settings_nvd_defaults(monkeypatch):
    monkeypatch.delenv("SAIR_NVD_API_KEY", raising=False)
    s = Settings()
    assert s.nvd_api_key is None
    assert s.nvd_cache_dir == Path("data/nvd-cache")
    assert s.nvd_fetch_timeout == 30.0

def test_settings_nvd_api_key_from_env(monkeypatch):
    monkeypatch.setenv("SAIR_NVD_API_KEY", "env-key")
    assert Settings().nvd_api_key == "env-key"

def test_cli_ok_returns_zero(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "a.jsonl"))  # keep audit in tmp
    get_settings.cache_clear()
    code = main(["CVE-2099-0001", "--role", "research_analyst"], source=FixtureCveSource())
    assert code == 0
    assert "CVE-2099-0001" in capsys.readouterr().out

def test_cli_not_found_returns_nonzero(tmp_path, monkeypatch):
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "a.jsonl"))
    get_settings.cache_clear()
    assert main(["CVE-2099-9999", "--role", "research_analyst"], source=FixtureCveSource()) != 0
```

(Confirm the audit-path env var name against `config.py` while writing the test; use the real one.)

- [ ] **Step 2: Run, verify fail** — `.venv/bin/python -m pytest tests/test_config.py tests/test_fetch_cve.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement.** Add the three fields to `Settings`. Add `main(argv=None, *, source=None)`: `argparse` for `cve_id` (positional) + `--role` (default `"research_analyst"`); if `source is None`, `s = get_settings(); source = CachingCveSource(NvdApiSource(api_key=s.nvd_api_key, timeout=s.nvd_fetch_timeout), s.nvd_cache_dir)`; `res = research_from_source(cve_id, role=role, source=source, audit_path=get_settings().audit_log_path)`; print outcome + `res.answer`; `return 0 if res.outcome is Outcome.OK else 1`. Add `if __name__ == "__main__": raise SystemExit(main())`.
- [ ] **Step 4: Run, verify pass** — Expected: PASS.
- [ ] **Step 5: Lint/type** — ruff + black + mypy. Expected: clean.
- [ ] **Step 6: Commit** (`feat(ingestion): add fetch-cve CLI + NVD settings`), with footer.

---

## Task 5: live integration test (CI-excluded)

**Files:**
- Create: `tests/test_nvd_fetch_integration.py`

**Interfaces:**
- Consumes: `NvdApiSource`, `CachingCveSource`, `research_from_source`, `nvd.load`, `Outcome`.

- [ ] **Step 1: Write the test**, marked `@pytest.mark.integration`, hitting live NVD for a long-published real CVE (`CVE-2021-44228`), keyless. Skip (not fail) on unreachable/rate-limited:

```python
@pytest.mark.integration
def test_live_nvd_fetch_to_cited_answer(tmp_path):
    source = CachingCveSource(NvdApiSource(), tmp_path / "cache")
    try:
        docs = nvd.load(source.fetch_raw("CVE-2021-44228"))
    except ValueError as exc:
        pytest.skip(f"NVD unreachable/rate-limited: {exc}")
    assert docs and docs[0].document.document_id == "CVE-2021-44228"
    res = research_from_source(
        "CVE-2021-44228", role="research_analyst",
        source=source, audit_path=tmp_path / "audit.jsonl")
    assert res.outcome is Outcome.OK
    assert any(c.document_id == "CVE-2021-44228" for c in res.citations)
```

(Confirm the `IngestedDocument` accessor for the id — `docs[0].document.document_id` — against `ingestion/ingested.py` while writing; use the real attribute path.)

- [ ] **Step 2: Verify it is excluded from the default suite** — `.venv/bin/python -m pytest -q` runs green **without** making a network call (the marker is filtered). Then confirm it is collectable: `.venv/bin/python -m pytest -m integration --co -q` lists it.
- [ ] **Step 3: Lint/type** — ruff + black + mypy. Expected: clean.
- [ ] **Step 4: Commit** (`test(ingestion): add CI-excluded live NVD integration test`), with footer.

---

## Self-review notes

- **Spec coverage:** port (T1), `NvdApiSource` (T1), `CachingCveSource` + persist-gate (T2), `research_from_source` (T3), config (T4), CLI (T4), hermetic unit tests (T1–T4), one gated integration test (T5). All §7 items and §8 tests mapped.
- **Type consistency:** `CveSource.fetch_raw(cve_id: str) -> bytes` used identically in T1–T5; `research_from_source(cve_id, *, role, source, audit_path)` used by T3/T4/T5; `main(argv=None, *, source=None) -> int` in T4.
- **Review Focus:** empty-feed (T2), malformed body (T2), absent-id→NOT_FOUND (T3), api_key-not-leaked (T1), malformed-cve_id (T1+T2) — each has a named test above.
- **Two builder confirmations folded in as inline notes:** the audit-path env var name (T4 Step 1) and the `IngestedDocument` id accessor (T5 Step 1) — both say "confirm against the real file while writing," not guessed here.
