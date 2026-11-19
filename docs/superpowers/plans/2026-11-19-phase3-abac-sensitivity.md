# ABAC sensitivity tier + two-user disclosure test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give documents a within-PUBLIC `sensitivity` tier (ROUTINE/RESTRICTED) enforced in the pre-retrieval `authorize` gate so `RESTRICTED` documents are retrievable only by `senior_analyst`, and prove with a two-user information-disclosure test that a `research_analyst` cannot obtain them on any path.

**Architecture:** One enum + one defaulted field on `ResearchDocument`; one ABAC check added to `authorize`. The `ResearchService` scope computation already consumes `authorize`, so the whole spine (id-routes + search + the Week-9 `AgentToolset`) honors the tier with no further change. Default `ROUTINE` keeps the existing corpus and all 199 tests unchanged.

**Tech Stack:** Python 3.12, pydantic (present), stdlib only otherwise; no new dependency.

**Spec:** `docs/superpowers/specs/2026-11-19-phase3-abac-sensitivity-design.md`

## Global Constraints

- stdlib + existing deps only, no new dependency. Deterministic, offline, hermetic. **PUBLIC/synthetic only** — `RESTRICTED` is a sensitivity within PUBLIC, never a new classification.
- Backward compatible: `sensitivity` defaults to `ROUTINE`; no existing `ResearchDocument` construction or `authorize` call changes behavior.
- **Do NOT modify** the loaders, routes, `deps`, `ResearchService`, or `AgentToolset` — they consume the schema/`authorize` unchanged.
- Deny-by-default: the RBAC allowlist is checked before the tier; a non-retrieval role is denied regardless of sensitivity.
- `ruff`/`black`/`mypy` clean, line length 100. Every commit ends with the attribution footer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU`.

## Review Focus

1. **RESTRICTED invisible to the lower role on every path** — id-route NOT_FOUND (no existence oracle) *and* excluded from search results/answer/citations — Task 2 `test_access_control`.
2. **Deny-by-default order** — RBAC allowlist before the tier; a non-retrieval role is denied a RESTRICTED doc — Task 1 `test_restricted_denied_role`.
3. **Backward compatibility** — default `ROUTINE`; 199 existing tests stay green, corpus stays routine — Task 1 `test_default_sensitivity_is_routine` + full suite.
4. **ABAC is pre-retrieval** — the tier lives in `authorize`, consumed by the service's scope computation — Task 1/Task 2.
5. **Zero unexpected blast radius** — only schema.py, authz.py, tests, roles.md, ROADMAP in the diff — final review.

---

### Task 1: `Sensitivity` tier in the schema + the `authorize` ABAC check

**Files:**
- Modify: `src/secure_ai_research/ingestion/schema.py` (add `Sensitivity` enum + `ResearchDocument.sensitivity` field)
- Modify: `src/secure_ai_research/retrieval/authz.py` (add the tier check)
- Test: `tests/test_authz.py` (extend); `tests/test_schema.py` (extend)

**Interfaces:**
- Consumes: `Classification`, `ResearchDocument` (existing).
- Produces: `Sensitivity` (StrEnum: `ROUTINE`, `RESTRICTED`); `ResearchDocument.sensitivity: Sensitivity = Sensitivity.ROUTINE`; `authorize(role, doc)` unchanged signature, now also denying `RESTRICTED` to any role not in `_RESTRICTED_ROLES = frozenset({"senior_analyst"})`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_schema.py`, add:
```python
def test_default_sensitivity_is_routine():
    from secure_ai_research.ingestion.schema import Sensitivity
    doc = _a_public_document()  # reuse the module's existing builder / construct inline
    assert doc.sensitivity is Sensitivity.ROUTINE
```
In `tests/test_authz.py`, add (reusing its `_doc()` helper, extended to take a sensitivity):
```python
def test_restricted_requires_senior():
    from secure_ai_research.ingestion.schema import Sensitivity
    restricted = _doc(sensitivity=Sensitivity.RESTRICTED)
    assert authorize("senior_analyst", restricted) is True
    assert authorize("research_analyst", restricted) is False

def test_routine_retrievable_by_both():
    assert authorize("research_analyst", _doc()) is True
    assert authorize("senior_analyst", _doc()) is True

def test_restricted_denied_role_still_denied():
    from secure_ai_research.ingestion.schema import Sensitivity
    restricted = _doc(sensitivity=Sensitivity.RESTRICTED)
    for role in ("security_auditor", "administrator", ""):
        assert authorize(role, restricted) is False
```
(Extend `test_authz.py`'s `_doc()` to accept `sensitivity: Sensitivity = Sensitivity.ROUTINE` and pass it through.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_authz.py tests/test_schema.py -q`
Expected: FAIL — `cannot import name 'Sensitivity'` / `ResearchDocument` has no `sensitivity`.

- [ ] **Step 3: Add `Sensitivity` + the field** in `schema.py`

Add the `Sensitivity(StrEnum)` with `ROUTINE`/`RESTRICTED` (docstring: an ABAC attribute within PUBLIC, not a classification). Add `sensitivity: Sensitivity = Sensitivity.ROUTINE` to `ResearchDocument` after `classification`.

- [ ] **Step 4: Add the ABAC check** in `authz.py`

Import `Sensitivity`. Add `_RESTRICTED_ROLES = frozenset({"senior_analyst"})`. Rewrite `authorize` per design §6.2: strip role; deny if not in `_ALLOWED_ROLES`; deny if `doc.classification != PUBLIC`; deny if `doc.sensitivity == Sensitivity.RESTRICTED and role not in _RESTRICTED_ROLES`; else True. Update the module docstring to mention the tier.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_authz.py tests/test_schema.py -q`
Expected: PASS.

- [ ] **Step 6: Full suite (backward-compat gate)**

Run: `.venv/bin/pytest -q`
Expected: green — the defaulted field + the new check don't disturb the all-ROUTINE corpus. Record the count.

- [ ] **Step 7: Lint + commit**

Run: `.venv/bin/ruff check . && .venv/bin/black --check . && .venv/bin/mypy`
```bash
git add src/secure_ai_research/ingestion/schema.py src/secure_ai_research/retrieval/authz.py tests/test_authz.py tests/test_schema.py
git commit   # feat(authz): within-PUBLIC sensitivity tier (RESTRICTED → senior_analyst only)  (+ footer)
```

---

### Task 2: Two-user information-disclosure test + role-model docs

**Files:**
- Test: `tests/test_access_control.py` (new)
- Modify: `infrastructure/identity/roles.md` (document the tier); `ROADMAP.md` (tick Week 10)

**Interfaces:**
- Consumes: `Sensitivity`, `ResearchDocument`, `IngestedDocument`, `ResearchService` (`research_cve`/`search` + `Outcome`), `authorize`, `HashingEmbedder`, `InMemoryVectorStore`, `AgentToolset`, `read_records`.
- Produces: the disclosure test + docs. No new code interface.

- [ ] **Step 1: Write the failing test** `tests/test_access_control.py`

Hermetic service on a temp audit, indexed with a ROUTINE CVE doc (`CVE-2021-44228`, text "log4j …") and a RESTRICTED CVE-shaped doc (`CVE-2099-5000`, a synthetic internal advisory, `sensitivity=RESTRICTED`, text containing a distinctive token e.g. `"zerberus-internal-only"`). Cases:
```python
def test_senior_can_retrieve_restricted(tmp_path):
    svc = _service(tmp_path)
    assert svc.research_cve("CVE-2099-5000", role="senior_analyst").outcome is Outcome.OK

def test_analyst_cannot_retrieve_restricted_no_oracle(tmp_path):
    svc = _service(tmp_path)
    restricted = svc.research_cve("CVE-2099-5000", role="research_analyst")
    absent = svc.research_cve("CVE-1999-0001", role="research_analyst")  # genuinely absent
    assert restricted.outcome is absent.outcome is Outcome.NOT_FOUND
    assert restricted.citations == absent.citations == []

def test_restricted_token_never_in_analyst_search(tmp_path):
    svc = _service(tmp_path)
    analyst = svc.search("zerberus-internal-only", role="research_analyst")
    assert all("CVE-2099-5000" != c.document_id for c in analyst.citations)
    assert "zerberus-internal-only" not in analyst.answer
    senior = svc.search("zerberus-internal-only", role="senior_analyst")
    assert any(c.document_id == "CVE-2099-5000" for c in senior.citations)

def test_two_users_through_agent_toolset(tmp_path):
    svc = _service(tmp_path)
    assert AgentToolset(svc, role="senior_analyst").search_cve("CVE-2099-5000").outcome is Outcome.OK
    assert AgentToolset(svc, role="research_analyst").search_cve("CVE-2099-5000").outcome is Outcome.NOT_FOUND
```

- [ ] **Step 2: Run to verify it fails first**

Run: `.venv/bin/pytest tests/test_access_control.py -q`
Expected: the test module is new; if Task 1 is already merged it may PASS immediately. If so, that is not TDD proof — temporarily set the restricted doc's `sensitivity=Sensitivity.ROUTINE`, run, and watch `test_analyst_cannot_retrieve_restricted_no_oracle` FAIL (analyst gets OK, token leaks), confirming the test discriminates; then restore `RESTRICTED` and watch it pass. (This is the watch-it-fail step for an integration test whose mechanism already exists.)

- [ ] **Step 3: Confirm it passes**

Run: `.venv/bin/pytest tests/test_access_control.py -q`
Expected: PASS (all four).

- [ ] **Step 4: Document the tier** in `infrastructure/identity/roles.md`

Add a short subsection: within PUBLIC, documents carry a `sensitivity` (`ROUTINE`/`RESTRICTED`); `ROUTINE` retrievable by any retrieval role, `RESTRICTED` only by `senior_analyst` — the concrete form of "wider retrieval scope". State it is **not** a classification lane (still PUBLIC) and is enforced in the pre-retrieval `authorize` gate.

- [ ] **Step 5: Tick ROADMAP Week 10**

Change the Week-10 line `- [ ] Week 10 — Role model + ABAC on retrieval; deny-by-default; two-user information-disclosure test` to `- [x]`.

- [ ] **Step 6: Full suite + verify diff + commit**

Run: `.venv/bin/pytest -q` — green.
Run: `git diff --stat main..HEAD` — only schema.py, authz.py, the tests, roles.md, ROADMAP, + design/plan docs.
```bash
git add tests/test_access_control.py infrastructure/identity/roles.md ROADMAP.md
git commit   # test(authz): two-user information-disclosure test + document the sensitivity tier  (+ footer)
```

---

## Final checks (before review)

- [ ] `.venv/bin/pytest -q` — full suite green (hermetic).
- [ ] `.venv/bin/ruff check . && .venv/bin/black --check . && .venv/bin/mypy` — clean.
- [ ] `git diff --stat main..HEAD` — only schema.py, authz.py, test_authz.py, test_schema.py, test_access_control.py, roles.md, ROADMAP, + design + plan.
