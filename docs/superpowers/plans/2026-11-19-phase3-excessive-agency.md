# Phase 3 slice 4 (FINAL) — Excessive-agency guards + close live-fetch side-channel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the opt-in live-fetch existence side-channel (make it a senior-only capability) and add a deterministic rate-limit / call-budget guard + a pinned read-only tool surface to `AgentToolset`.

**Architecture:** Two independent changes. (1) A one-line role gate in `_research`'s fetch-on-miss branch backed by a `may_live_fetch(role)` policy helper in `authz.py`, so only a role with no "present-but-hidden" PUBLIC class (today `senior_analyst`) ever triggers a fetch — collapsing absent vs present-but-RESTRICTED to identical response **and** fetch behavior for every other role. (2) A stdlib token-bucket `RateLimiter` (injected clock) + `RateLimitExceeded`, wired as an **optional** `AgentToolset` guard that acquires before validation/delegation, plus a surface-pin test.

**Tech Stack:** Python 3.12, stdlib + pydantic. `.venv/bin/pytest -q` (hermetic; `-m "not integration"` deselects the 2 live NVD tests), `.venv/bin/ruff check .`, `.venv/bin/black --check .`, `.venv/bin/mypy`.

**Spec:** docs/superpowers/specs/2026-11-19-phase3-excessive-agency-design.md

## Global Constraints

- stdlib + pydantic only; **no new runtime dependency**. Deterministic, offline, hermetic. PUBLIC/synthetic only.
- `ruff`/`black`/`mypy` clean, line length 100.
- **Backward compatible:** default-constructed `AgentToolset(svc, role=...)` behaves exactly as before (no limiter). Default `ResearchService` wiring unchanged.
- The side-channel fix is confined to `authz.py` (+helper) and the single `_research` fetch-gate line; **no** change to retrieval assembly, chunking, `build_report`, loaders, schema, routes, or `deps`.
- Attribution footer on every commit (Co-Authored-By: Claude Opus 4.8 + Claude-Session line).

## Review Focus

- **Any non-senior authorized role never fetches:** a role authorized for ROUTINE but not in `_FETCH_ROLES` (e.g. `research_analyst`) triggers **zero** fetches for an absent id — not just for a present-RESTRICTED id. Covered by Task 1 closure test (`spy.calls == 0` for both). *If this regressed, the oracle reopens.*
- **Reject discipline writes nothing:** an over-budget `AgentToolset` call raises `RateLimitExceeded` and leaves the audit log with exactly the records of the **allowed** calls (zero from the rejected one), does not delegate, does not echo the arg. Covered by Task 2 audit-count + spy assertions.
- **RateLimiter refill is real, and caps:** after the budget is spent, advancing the injected clock refills and a later `acquire` succeeds; advancing it arbitrarily far never allows more than `capacity` in one burst. Covered by Task 2 refill + cap tests.
- **`capacity=0` denies everything:** a zero-capacity limiter raises on the first `acquire`. Covered by Task 2 edge test.
- **Whitespace role:** `may_live_fetch(" senior_analyst ")` is eligible (`.strip()`, matching `_research`'s `analyst_id`); `may_live_fetch("")` is not. Covered by Task 1 policy unit test.

---

### Task 1: Close the live-fetch existence side-channel (senior-only fetch)

**Files:**
- Modify: `src/secure_ai_research/retrieval/authz.py` (add `_FETCH_ROLES` + `may_live_fetch`)
- Modify: `src/secure_ai_research/research_service.py` (import `may_live_fetch`; add it to the fetch-gate condition — the line currently `if fetch_missing is not None and doc_id not in self._docs:`)
- Modify: `tests/test_research_service.py` (re-target fetch-mechanism tests to `senior_analyst`; add policy + closure tests)
- Modify: `tests/test_api.py` (re-target the 3 fetch-firing endpoint tests to `senior_analyst`)
- Modify: `tests/test_nvd_fetch_integration.py` (re-target the endpoint-based live test to `senior_analyst`; leave any `research_from_source` pre-index test as-is)
- Modify: `infrastructure/identity/roles.md` (document live-fetch as a senior-only capability + the widen-in-lockstep invariant)

**Interfaces:**
- Produces: `may_live_fetch(role: str) -> bool` in `retrieval/authz.py` (True iff `role.strip()` ∈ `_FETCH_ROLES`, where `_FETCH_ROLES = _RESTRICTED_ROLES = frozenset({"senior_analyst"})`).
- Consumes: existing `_research(doc_id, *, role, objective, fetch_missing)`; the fetch branch at `research_service.py` ~line 146.

- [ ] **Step 1: Write the failing policy unit test**

```python
# tests/test_research_service.py
from secure_ai_research.retrieval.authz import may_live_fetch

def test_may_live_fetch_is_senior_only():
    assert may_live_fetch("senior_analyst") is True
    assert may_live_fetch(" senior_analyst ") is True   # stripped, like analyst_id
    assert may_live_fetch("research_analyst") is False
    assert may_live_fetch("") is False
    assert may_live_fetch("security_auditor") is False
```

- [ ] **Step 2: Run it, verify it fails** — Run: `.venv/bin/pytest tests/test_research_service.py::test_may_live_fetch_is_senior_only -q`. Expected: FAIL (ImportError / `may_live_fetch` undefined).

- [ ] **Step 3: Implement `may_live_fetch` in `authz.py`** — add after `_RESTRICTED_ROLES`:
```python
_FETCH_ROLES = _RESTRICTED_ROLES  # see design §7.1: only a role with no present-but-hidden
                                  # PUBLIC class may fetch, or the existence oracle reopens.

def may_live_fetch(role: str) -> bool:
    """Whether ``role`` may trigger opt-in live fetch-on-miss (see ``_FETCH_ROLES``)."""
    return role.strip() in _FETCH_ROLES
```
Add a module comment block (design §7.1 rationale) above `_FETCH_ROLES`.

- [ ] **Step 4: Run it, verify it passes** — Run: same command. Expected: PASS.

- [ ] **Step 5: Re-target the fetch-mechanism tests to `senior_analyst`** (they exercise the fetch firing; the eligible role is now senior). In `tests/test_research_service.py` change `role="research_analyst"` → `role="senior_analyst"` **only** in: `test_fetch_on_miss_returns_cited_answer`, `test_fetch_absent_returns_not_found`, `test_fetch_unavailable_returns_fetch_error`, `test_fetch_oserror_becomes_fetch_error`, `test_fetch_unexpected_exception_becomes_fetch_error`, and the **absent_audit + error_audit** calls in `test_fetch_records_name_the_fetch` (leave its `never_audit` call — no fetcher — as `research_analyst`). Do **not** touch `test_denied_role_never_fetches` (role `""`), `test_miss_without_fetch_missing_is_not_found`, or `test_index_if_absent_is_idempotent`. In `tests/test_api.py` change `X-Role` `research_analyst` → `senior_analyst` in `test_fetch_on_miss_is_200_with_citation`, `test_fetch_absent_is_404`, `test_fetch_unavailable_is_503` (leave `test_unknown_cve_without_fetch_is_404` and `test_unauthorized_never_fetches`). In `tests/test_nvd_fetch_integration.py` re-target the endpoint call (X-Role) to `senior_analyst`; leave a `research_from_source(...)` call as-is (pre-index path, no gate).

- [ ] **Step 6: Run the touched suites, verify still green** (pre-gate, `senior_analyst` already fetches) — Run: `.venv/bin/pytest tests/test_research_service.py tests/test_api.py -q`. Expected: PASS (re-target is a role swap to an also-eligible role; no behavior change yet).

- [ ] **Step 7: Write the failing closure test** (the heart of property I)

```python
# tests/test_research_service.py  — absent and present-RESTRICTED are indistinguishable to a
# non-senior role: identical response AND zero fetches (no timing/egress oracle); senior still fetches.
def test_live_fetch_is_senior_only_no_existence_oracle(tmp_path):
    spy = _FakeFetch(docs=[_one_doc("CVE-2099-7777")])
    svc = ResearchService(
        HashingEmbedder(), InMemoryVectorStore(), authorize, tmp_path / "a.jsonl",
        fetch_missing=spy,
    )
    svc.index(_docs() + [_one_doc("CVE-2099-6001", sensitivity=Sensitivity.RESTRICTED)])

    present_restricted = svc.research_cve("CVE-2099-6001", role="research_analyst")  # in corpus, hidden
    absent = svc.research_cve("CVE-2099-7777", role="research_analyst")              # not in corpus
    assert present_restricted.outcome is Outcome.NOT_FOUND
    assert absent.outcome is Outcome.NOT_FOUND
    # response-level: identical observable fields
    assert (present_restricted.answer, [c.document_id for c in present_restricted.citations]) == ("", [])
    assert (absent.answer, [c.document_id for c in absent.citations]) == ("", [])
    # timing/egress-level: the analyst never fetched in EITHER case — the oracle is closed
    assert spy.calls == 0
    # senior is the eligible fetcher: absent fires exactly one fetch; present-RESTRICTED is retrievable
    assert svc.research_cve("CVE-2099-7777", role="senior_analyst").outcome is Outcome.OK
    assert spy.calls == 1
    assert svc.research_cve("CVE-2099-6001", role="senior_analyst").outcome is Outcome.OK
```

Note for builder: `_one_doc` must accept a `sensitivity` kwarg (it may already; if not, add an optional `sensitivity: Sensitivity = Sensitivity.ROUTINE` param threaded into the `ResearchDocument`, mirroring `test_injection_harness._cve_doc`). Import `Sensitivity` if not already imported.

- [ ] **Step 8: Run it, verify it fails** — Run: `.venv/bin/pytest tests/test_research_service.py::test_live_fetch_is_senior_only_no_existence_oracle -q`. Expected: FAIL — pre-gate, the analyst's absent-id request fires the fetch, so `spy.calls == 1` (not 0) at the first assertion (and `absent.outcome` may be OK, not NOT_FOUND).

- [ ] **Step 9: Add the role gate to `_research`** — change the fetch-branch condition to:
```python
if fetch_missing is not None and may_live_fetch(role) and doc_id not in self._docs:
```
Import `may_live_fetch` from `.retrieval.authz` beside the existing authz import. Update the branch's comment to note fetch is now senior-only (closes the existence side-channel). Nothing else in `_research` changes.

- [ ] **Step 10: Run the closure test + full suite** — Run: `.venv/bin/pytest tests/test_research_service.py::test_live_fetch_is_senior_only_no_existence_oracle -q` (Expected PASS), then `.venv/bin/pytest -q -m "not integration"` (Expected PASS — all re-targeted tests green).

- [ ] **Step 11: Update `infrastructure/identity/roles.md`** — one short paragraph: opt-in live fetch-on-miss is a `senior_analyst` capability (it does network egress and writes the corpus by indexing the fetched doc); this also closes the fetch-timing existence side-channel; the fetch-eligible set must stay = the roles that can retrieve every PUBLIC sensitivity tier, widened only in lockstep with any new tier.

- [ ] **Step 12: Lint + commit**
```bash
.venv/bin/ruff check . && .venv/bin/black --check . && .venv/bin/mypy
git add -A && git commit  # feat(authz): gate live-fetch to senior_analyst — close existence side-channel
```

### Task 2: Rate-limit / call-budget guard + read-only surface pin on AgentToolset

**Files:**
- Create: `src/secure_ai_research/agents/rate_limit.py` (`RateLimiter`, `RateLimitExceeded`)
- Create: `tests/test_rate_limit.py`
- Modify: `src/secure_ai_research/agents/functions.py` (optional `rate_limiter` param + acquire-first in each tool; read-only docstring)
- Modify: `tests/test_access_control.py` (add AgentToolset rate-limit + read-only surface tests) **or** a new `tests/test_agent_rate_limit.py` — builder's call; keep AgentToolset tests together.
- Modify: `ROADMAP.md` (tick Week 12)

**Interfaces:**
- Produces: `RateLimiter(capacity: int, refill_per_second: float = 0.0, *, clock: Callable[[], float] = time.monotonic)` with `acquire(tokens: int = 1) -> None` raising `RateLimitExceeded`. `AgentToolset(service, *, role, rate_limiter: RateLimiter | None = None)`.
- Consumes: existing `AgentToolset` tools (`search_cve`/`search_attack`/`search_research`) and `ResearchService`.

- [ ] **Step 1: Write failing RateLimiter unit tests**

```python
# tests/test_rate_limit.py
import pytest
from secure_ai_research.agents.rate_limit import RateLimiter, RateLimitExceeded

def test_budget_without_refill_exhausts():
    rl = RateLimiter(capacity=2)                       # no refill
    rl.acquire(); rl.acquire()
    with pytest.raises(RateLimitExceeded):
        rl.acquire()

def test_zero_capacity_denies_first_call():
    with pytest.raises(RateLimitExceeded):
        RateLimiter(capacity=0).acquire()

def test_refill_with_injected_clock_restores_then_caps():
    now = [0.0]
    rl = RateLimiter(capacity=2, refill_per_second=1.0, clock=lambda: now[0])
    rl.acquire(); rl.acquire()
    with pytest.raises(RateLimitExceeded):
        rl.acquire()                                   # empty
    now[0] = 1.0
    rl.acquire()                                       # +1 token refilled
    with pytest.raises(RateLimitExceeded):
        rl.acquire()
    now[0] = 999.0
    rl.acquire(); rl.acquire()                         # capped at capacity (2), not 999
    with pytest.raises(RateLimitExceeded):
        rl.acquire()
```

- [ ] **Step 2: Run, verify fail** — Run: `.venv/bin/pytest tests/test_rate_limit.py -q`. Expected: FAIL (module/class missing).

- [ ] **Step 3: Implement `rate_limit.py`** — token bucket: store `capacity`, `refill_per_second`, `clock`, `_tokens = float(capacity)`, `_last = clock()`. `acquire(tokens=1)`: `now = clock(); _tokens = min(capacity, _tokens + (now - _last) * refill_per_second); _last = now`; if `_tokens >= tokens: _tokens -= tokens` else `raise RateLimitExceeded`. `RateLimitExceeded(Exception)`. Type the clock as `Callable[[], float]`.

- [ ] **Step 4: Run, verify pass** — Run: `.venv/bin/pytest tests/test_rate_limit.py -q`. Expected: PASS.

- [ ] **Step 5: Write failing AgentToolset guard tests** (reuse the existing hermetic service builder in the AgentToolset tests)

```python
def test_toolset_rate_limit_blocks_over_budget_without_delegating_or_auditing(tmp_path):
    svc = <hermetic ResearchService with a benign CVE indexed, audit at tmp_path/"a.jsonl">
    toolset = AgentToolset(svc, role="research_analyst", rate_limiter=RateLimiter(capacity=1))
    toolset.search_cve("CVE-2099-0001")                       # allowed
    audited_after_allowed = len(read_records(tmp_path / "a.jsonl"))
    with pytest.raises(RateLimitExceeded):
        toolset.search_cve("CVE-2099-0001")                   # over budget
    # reject wrote no audit record and did not delegate a second time
    assert len(read_records(tmp_path / "a.jsonl")) == audited_after_allowed

def test_toolset_rate_limit_fires_before_arg_validation(tmp_path):
    toolset = AgentToolset(svc, role="research_analyst", rate_limiter=RateLimiter(capacity=0))
    with pytest.raises(RateLimitExceeded):
        toolset.search_cve("not-a-valid-id")   # RateLimitExceeded, NOT ValueError — budget checked first

def test_toolset_default_has_no_limit(tmp_path):
    toolset = AgentToolset(svc, role="research_analyst")      # no limiter
    for _ in range(5):
        toolset.search_cve("CVE-2099-0001")                  # never raises

def test_toolset_public_surface_is_read_only():
    assert {m for m in vars(AgentToolset) if not m.startswith("_") and callable(getattr(AgentToolset, m))} == {
        "search_cve", "search_attack", "search_research",
    }
```

Builder: `test_toolset_public_surface_is_read_only` is a **characterization guard** (passes on current code; it pins the surface so a future mutating method trips it). Ledger it as such — it is not driving new behavior, so "watch it fail" does not apply; the other three are RED-first.

- [ ] **Step 6: Run, verify the behavior tests fail** — Run: `.venv/bin/pytest tests/<agent test file> -q -k "rate_limit or read_only"`. Expected: the three rate-limit tests FAIL (`AgentToolset.__init__` rejects `rate_limiter`); the surface test passes.

- [ ] **Step 7: Wire the limiter into `AgentToolset`** — add `rate_limiter: RateLimiter | None = None` to `__init__`, store `self._rate_limiter`. At the top of each of `search_cve`/`search_attack`/`search_research`, before arg validation: `if self._rate_limiter is not None: self._rate_limiter.acquire()`. Extend the class docstring: the toolset is read-only (retrieval only); the one write in the system — live fetch-on-miss — is senior-gated in the service; an over-budget call raises `RateLimitExceeded` before validation/delegation, with no echo and no audit.

- [ ] **Step 8: Run, verify pass + full suite** — Run: `.venv/bin/pytest tests/<agent test file> tests/test_rate_limit.py -q` (Expected PASS), then `.venv/bin/pytest -q -m "not integration"` (Expected PASS).

- [ ] **Step 9: Tick ROADMAP Week 12** — mark the Week-12 line `[x]` in `ROADMAP.md`.

- [ ] **Step 10: Lint + commit**
```bash
.venv/bin/ruff check . && .venv/bin/black --check . && .venv/bin/mypy
git add -A && git commit  # feat(agents): optional rate-limit/call-budget guard + read-only surface pin; tick Week 12
```
