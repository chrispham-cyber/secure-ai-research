# Phase 3 slice 2 — Role model + ABAC on retrieval (sensitivity tier) + two-user disclosure test

**Date:** 2026-11-19 · **Status:** design (approach chosen by Chris: Option A — ABAC sensitivity tier by role) · **ROADMAP:** Phase 3, Week 10

## 1. Intent / why

ROADMAP Phase 3 Week 10: *"Role model + ABAC on retrieval; deny-by-default; two-user information-disclosure test."* Today the authorization gate is pure RBAC with a trivial ABAC check: `authorize(role, doc)` passes iff `role ∈ {research_analyst, senior_analyst}` **and** `doc.classification == PUBLIC`. Because every document is PUBLIC and both retrieval roles see the same set, there is no second lane — so no information-disclosure boundary to test. `roles.md` already promises one: *"senior_analyst … wider retrieval scope."* This slice makes that scope difference real and proves, with a two-user test, that a lower-privilege analyst cannot obtain what only a senior analyst may see.

Chris chose **Option A**: a within-PUBLIC **sensitivity tier** as the ABAC attribute, rather than a tenant/ownership model (Option B) or implicit source-name lanes (Option C).

## 2. Goals

- A `Sensitivity` tier on `ResearchDocument`: `ROUTINE` (default) and `RESTRICTED`, **within the PUBLIC lane** (not a new classification — posture unchanged).
- `authorize` enforces the tier as ABAC on top of the existing RBAC + classification check, deny-by-default: a `RESTRICTED` document is retrievable **only** by `senior_analyst`; `ROUTINE` by any allowed retrieval role.
- The whole retrieval spine honors it automatically (the service builds its authorized scope via `authorize`), so a `RESTRICTED` doc never enters a `research_analyst`'s scope on **any** path — id-route or search — and absence is indistinguishable from unauthorized (no existence oracle).
- A **two-user information-disclosure test**: over one corpus holding a `ROUTINE` and a `RESTRICTED` document, `senior_analyst` retrieves the restricted one and `research_analyst` cannot — asserted at the service layer and end-to-end through the Week-9 `AgentToolset` boundary.
- `roles.md` documents the sensitivity tier as the concrete realization of "wider retrieval scope"; ROADMAP Week-10 lines ticked.

## 3. Non-goals (this slice)

- **No `Role` enum / no roles.py refactor.** The role model stays string-based (`authz` allowlists), consistent with the existing code; roles.md remains the human-readable role model. Introducing an enum would churn the X-Role parsing and every call site for no behavior gain (YAGNI).
- **No non-PUBLIC classification.** `RESTRICTED` is a *sensitivity* within PUBLIC, not CUI/classified — the repo stays PUBLIC/synthetic only.
- **No change to the loaders, the routes, `deps`, `ResearchService`, or the Week-9 `AgentToolset`.** They all consume `authorize`/the schema unchanged; the new field defaults to `ROUTINE`, so the existing synthetic corpus stays entirely routine and their behavior is unchanged.
- **No per-tier audit field, no admin UI, no classification-change workflow.** Out of scope.

## 4. Anti-goals (would make this a failure even if green)

- A `RESTRICTED` document leaking into a `research_analyst`'s results, answer, citations, or an existence signal (NOT_FOUND vs a distinguishable "forbidden").
- The sensitivity check applied *after* retrieval instead of inside the pre-retrieval `authorize` gate.
- A default that makes existing documents `RESTRICTED` (would silently change the corpus and break the all-public assumption).
- Deny-by-default weakened: a role outside the retrieval allowlist must still be denied regardless of sensitivity.

## 5. Constraints

- Python 3.12, stdlib + pydantic (already present), no new dependency. Deterministic, offline, hermetic. PUBLIC/synthetic only.
- `ruff`/`black`/`mypy` clean, line length 100. Attribution footer on every commit.
- Backward compatible: `sensitivity` defaults to `ROUTINE`; no existing construction of `ResearchDocument` or call to `authorize` changes behavior.

## 6. Design (the "how" decided)

### 6.1 `src/secure_ai_research/ingestion/schema.py`

Add an enum and one field:

```python
class Sensitivity(StrEnum):
    """Retrieval sensitivity *within* the PUBLIC lane (ABAC attribute, not a classification)."""
    ROUTINE = "ROUTINE"
    RESTRICTED = "RESTRICTED"
```

On `ResearchDocument`, after `classification`:
```python
    sensitivity: Sensitivity = Sensitivity.ROUTINE
```
Default `ROUTINE` ⇒ every existing fixture/doc is routine; no loader touches it.

### 6.2 `src/secure_ai_research/retrieval/authz.py`

Add the ABAC tier check to the existing gate (deny-by-default preserved):

```python
_ALLOWED_ROLES = frozenset({"research_analyst", "senior_analyst"})
_RESTRICTED_ROLES = frozenset({"senior_analyst"})  # may retrieve RESTRICTED docs

def authorize(role: str, doc: ResearchDocument) -> bool:
    role = role.strip()
    if role not in _ALLOWED_ROLES:
        return False
    if doc.classification != Classification.PUBLIC:
        return False
    if doc.sensitivity == Sensitivity.RESTRICTED and role not in _RESTRICTED_ROLES:
        return False
    return True
```

No change anywhere else: `ResearchService` already computes `allowed = {did for … if self._authorize(role, doc)}`, so a `RESTRICTED` doc is simply absent from a `research_analyst`'s `allowed`/`scope`, yielding the existing NOT_FOUND / excluded-from-search behavior (no existence oracle) by construction.

### 6.3 Tests

**`tests/test_authz.py`** (extend) — the ABAC matrix:
- `ROUTINE` + `research_analyst` → True; + `senior_analyst` → True (unchanged).
- `RESTRICTED` + `research_analyst` → **False**; + `senior_analyst` → **True**.
- `RESTRICTED` + a denied role (`security_auditor`, `administrator`, `""`) → False (RBAC still wins first).
- A `ResearchDocument` built without `sensitivity` defaults to `ROUTINE` and is retrievable by `research_analyst` (backward-compat pin).

**`tests/test_access_control.py`** (new) — the two-user information-disclosure test, built on a hermetic service + temp audit with a `ROUTINE` CVE doc and a `RESTRICTED` one (e.g. `INTERNAL-ADV-1`, a synthetic internal advisory, clearly labeled PUBLIC-but-restricted):
- `senior_analyst` via `service.research_cve("INTERNAL-ADV-1")` → `OK`, cited.
- `research_analyst` via the same → `NOT_FOUND`, empty citations — identical to a genuinely absent id (asserted against a fake id too: no existence oracle).
- `service.search(<token only in the restricted doc>, role="research_analyst")` → the restricted id/text appears in **no** citation and **not** in the answer; same search as `senior_analyst` → it does appear.
- **End-to-end through the Week-9 boundary:** two `AgentToolset`s over the same service — `AgentToolset(svc, role="senior_analyst").search_cve("INTERNAL-ADV-1")` → OK; `AgentToolset(svc, role="research_analyst").search_cve("INTERNAL-ADV-1")` → NOT_FOUND. (Uses a CVE-shaped id so it passes the toolset's `search_cve` arg validation; the "internal advisory" is modeled as a restricted CVE record.)

> Note: the restricted fixture doc needs a `cve_id`-shaped `document_id` to be reachable through `AgentToolset.search_cve`'s `^CVE-\d{4}-\d{4,}$` validation, so model it as a restricted CVE (e.g. `CVE-2099-5000`) rather than a `INTERNAL-ADV-1` literal. The service id-route matches on `document_id`, so this is consistent.

### 6.4 `infrastructure/identity/roles.md` + `ROADMAP.md`

- roles.md: a short subsection making the ABAC tier explicit — within PUBLIC, documents carry a `sensitivity` (`ROUTINE`/`RESTRICTED`); `ROUTINE` is retrievable by any retrieval role, `RESTRICTED` only by `senior_analyst` (the concrete form of "wider retrieval scope"). State it is **not** a classification lane (still PUBLIC) and that enforcement is in the pre-retrieval `authorize` gate.
- ROADMAP: tick Week 10's "Role model + ABAC on retrieval; deny-by-default; two-user information-disclosure test".

## 7. What's left to the builder

- Exact synthetic restricted-doc content and the token used to prove search exclusion (pick a distinctive token present only in the restricted doc).
- Docstring/comment wording; the roles.md subsection phrasing.

## 8. Review focus (for the final whole-branch review)

1. **RESTRICTED is invisible to the lower role on every path** — id-route NOT_FOUND (no existence oracle) *and* excluded from search results/answer/citations — test_access_control covers both; confirm nothing surfaces the restricted text to `research_analyst`.
2. **Deny-by-default order** — RBAC allowlist is checked before the tier, so a non-retrieval role is denied a RESTRICTED doc too (not accidentally granted).
3. **Backward compatibility** — default `ROUTINE`; the 199 existing tests stay green and the whole packaged corpus stays routine (no loader change).
4. **ABAC is pre-retrieval** — the tier lives in `authorize`, consumed by the service's scope computation, not bolted on after retrieval.
5. **Zero unexpected blast radius** — only schema.py (+field/enum), authz.py (+check), tests, roles.md, ROADMAP in the diff.
