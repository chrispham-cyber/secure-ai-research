# Phase 3 slice 1 — Agent tool functions with permission checks outside the LLM

**Date:** 2026-11-19 · **Status:** design (proceed-without-approval per the established in-posture batch pattern) · **ROADMAP:** Phase 3, Week 9

## 1. Intent / why

ROADMAP Phase 3 Week 9: *"Agent tool functions (`search_cve/attack/research`) with permission checks **outside** the LLM."* Today `agents/functions.py` holds three `NotImplementedError` stubs whose docstring already states the core rule — *the model may request a function; the application independently decides if it is permitted*. This slice makes that rule real and tested.

The threat it closes is **excessive agency / confused-deputy escalation** (threat-model T7/T9): a model, or injected text a model ingests, must never be able to widen its own access by *requesting* a privileged action. `roles.md` already commits to the mechanism: *"A tool call is authorized against the caller's role, by application code, before it runs — the model cannot grant itself access by requesting a function… the model operates under its own constrained permission set, never the analyst's."* Week 9 builds the object that enforces exactly that.

## 2. Goals

- A role-bound **`AgentToolset`** — trusted application code constructs it with a **verified role** and the process `ResearchService`; the (hypothetical) model is handed the instance and may call its tools with **data arguments only**.
- Three tools preserving the ROADMAP-named verbs: `search_cve(cve_id)`, `search_attack(technique_id)`, `search_research(query)`, each returning the cited `ResearchResult` from the service's existing authorize-before-retrieve path.
- The caller's role is **bound at construction and immutable** — no tool method takes a role argument, so a model cannot change the principal it runs as.
- Every tool treats its argument as an **untrusted request**: a structurally invalid `cve_id` / `technique_id` / `query` is rejected **before** any retrieval or audit (fail-loud `ValueError`, naming the argument, never echoing a raw payload).
- Deny-by-default carries through: a tool invoked under an unauthorized role returns `Outcome.DENIED` with no citations — it retrieves nothing, and cannot distinguish a real document from an absent one (no existence oracle).
- Hermetic tests proving each property; the three stubs + their `test_stubs.py` entries retired (mirrors the KEV/Sigma loader slices).

## 3. Non-goals (this slice)

- **No agent *endpoint* / no LLM loop.** There is no LLM in posture (retrieval-only). The deliverable is the tool boundary object + tests, exactly as the stubs were module-level (no route). Wiring a toolset into a request principal is left to a later slice / Phase 5 identity.
- **No rate limits, no read-only *framework*, no injection-pattern arg scanning.** Those are Week 12 (excessive-agency guards). Week 9 does only the *essential* untrusted-input handling: reject structurally invalid arguments. The `AgentToolset` is deliberately the place those Week-12 guards will later attach.
- **No second access lane / no ABAC extension.** That is Week 10. Week 9 uses the authz gate and corpus exactly as they are.
- **No change to `authz`, `ResearchService`, the loaders, the routes, `deps`, or the schema.** Only `agents/functions.py` is rewritten and tests added.

## 4. Anti-goals (would make this a failure even if green)

- A tool that lets the model supply, override, or widen its own role.
- A permission check that lives *inside* a prompt / model output instead of in application code.
- An invalid or malicious argument reaching the service, producing retrieval, or writing an audit record before rejection.
- Returning raw documents that bypass the cited/audited `ResearchResult` discipline.
- Scope creep: building Week 10/11/12 features here.

## 5. Constraints

- Python 3.12, **stdlib-only at runtime**, no new dependency. Deterministic, offline, hermetic (no `@pytest.mark.integration`). PUBLIC/synthetic only.
- `ruff`/`black`/`mypy` clean, line length 100. Attribution footer on every commit.
- Reuse the existing argument shapes already enforced at the route: `cve_id` `^CVE-\d{4}-\d{4,}$`, `technique_id` `^T\d{4}(\.\d{3})?$`, `query` stripped, 1–512 chars (mirrors `SearchRequest`).

## 6. Approaches considered

- **(A) Role-bound `AgentToolset` class (CHOSEN).** Trusted code constructs `AgentToolset(service, role="research_analyst")`; the model holds the instance and calls `.search_cve("CVE-…")`. The role is an immutable instance attribute the model never sees a setter for; tools take only data args. *Why:* it is the literal realization of "the model operates under its own constrained permission set" — the principal is bound *outside* the model and cannot be reached through any tool argument. It is also the natural home for Week-12 guards (a rate-limit counter, read-only assertions) and a future per-request principal. One object, clear boundary.
- **(B) Module-level functions taking an explicit `role` parameter** (`search_cve(cve_id, *, role, service)`). Rejected: every call site must thread the role through, and a single wrong/model-influenced `role=` argument silently escalates — the exact confused-deputy failure this slice exists to prevent. Binding the role once, in a constructor called by trusted code, removes that whole class of mistake.
- **(C) Keep returning `list[ResearchDocument]`** (the stub's current return). Rejected: it would bypass the cited, audited `ResearchResult` the whole platform is built around, and give the caller raw documents with no outcome (DENIED vs NOT_FOUND vs OK) and no `research_id` for audit linkage.

## 7. Design (the "how" decided)

### 7.1 `src/secure_ai_research/agents/functions.py` (rewrite)

```python
class AgentToolset:
    """Role-bound tool belt handed to a model. The role is fixed by trusted
    application code at construction; tool methods take data arguments only, so
    a model can never change the principal it runs as. Each tool rejects a
    structurally invalid argument before any retrieval, then delegates to the
    service's authorize-before-retrieve path."""

    def __init__(self, service: ResearchService, *, role: str) -> None: ...

    def search_cve(self, cve_id: str) -> ResearchResult:        # validate ^CVE-…$ → service.research_cve(cve_id, role=self._role)
    def search_attack(self, technique_id: str) -> ResearchResult:  # validate ^T…$ → service.research_attack(technique_id, role=self._role)
    def search_research(self, query: str) -> ResearchResult:    # strip + 1..512 → service.search(query, role=self._role)
```

- `role` is stored as a private attribute `self._role`; there is no setter and no tool parameter accepts a role. (A model cannot widen its principal.)
- Argument validation runs first, in the method, before touching the service. Patterns as module constants `_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")`, `_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")`; `query` is `.strip()`-ed and must be 1–512 chars. On violation raise `ValueError("search_cve: cve_id is not a valid CVE identifier")` etc. — **name the argument, never interpolate the raw value** (a `query` may be an arbitrary/hostile payload; not echoing it avoids log-injection and payload leakage). This guarantees a malformed request writes **no audit record** (the service is never called).
- No limit parameter is exposed on `search_research` (the model cannot request an unbounded result set); the service's default applies. Tightening/rate-limiting is Week 12.
- The three old module-level stub functions are **removed** (not kept as wrappers — YAGNI; the class is the contract).

### 7.2 Tests — `tests/test_agent_tools.py`

Build a hermetic service on a temp audit log, indexed with a tiny synthetic corpus (one PUBLIC CVE doc, one ATT&CK doc) — not the packaged fixtures, so the test is self-contained. Then:

1. `test_search_cve_authorized_returns_cited_result` — role `research_analyst`, known CVE → `Outcome.OK`, non-empty citations, the CVE's id among them.
2. `test_search_attack_authorized_returns_result` — `research_analyst`, indexed technique → OK with a citation.
3. `test_search_research_authorized_ranks_corpus` — `research_analyst`, a query token in the corpus → OK, ≥1 citation.
4. `test_unauthorized_role_is_denied_and_retrieves_nothing` — role `security_auditor` (per roles.md may **not** retrieve) → `Outcome.DENIED`, empty citations, for all three tools.
5. `test_unauthorized_role_has_no_existence_oracle` — `security_auditor`, a *real* CVE id and a *fake* one both return `Outcome.DENIED` with identical (empty) shape — the toolset can't be used to probe existence.
6. `test_role_is_bound_not_a_tool_argument` — two toolsets over the **same** service, one `research_analyst` one `security_auditor`; the analyst gets OK, the auditor DENIED for the same `cve_id` — proving access is the bound role's, not anything the caller passed to the method. (Plus: `search_cve` signature has no `role` parameter — `inspect.signature`.)
7. `test_malformed_cve_id_raises_before_retrieval` — `search_cve("DROP TABLE")` raises `ValueError`; assert the audit log file has **zero** records written (validation precedes the service). Same for `search_attack("../etc")` and `search_research("   ")` (empty after strip) and an over-512-char query.
8. `test_malformed_argument_error_does_not_echo_payload` — the `ValueError` message for a hostile `query` does **not** contain the payload substring.
9. `test_authorized_call_emits_exactly_one_audit_record` — one `search_cve` → exactly one record via `read_records` (no double-audit by the toolset).

### 7.3 `tests/test_stubs.py` (edit)

Remove the three `functions.search_*` entries from `STUB_CALLS` and the now-unused `from secure_ai_research.agents import functions` import; `metrics.score` stays, and `test_adapter_stubs_raise_on_construction` (Ollama/PgVector) is untouched. (Mirrors retiring `kev.load`/`sigma.load`.)

## 8. What's left to the builder

- Exact wording of docstrings and `ValueError` messages (following the constraints above: name the arg, no payload echo).
- The synthetic corpus helper in the test (shape of the one CVE + one ATT&CK `IngestedDocument`); reuse the `ResearchDocument`/`IngestedDocument` constructors as the other ingestion tests do.
- Whether to keep `_RULE`/module docstring text — keep an updated module docstring stating the enforced rule and pointing at `roles.md`.

## 9. Review focus (for the final whole-branch review)

1. **Principal is unforgeable from the model side** — no tool method accepts or honors a role argument; the bound role is the only one used (test 6).
2. **Fail-closed on bad input** — a malformed/hostile argument never reaches the service, never retrieves, never audits; the error doesn't echo the payload (tests 7, 8).
3. **Deny-by-default + no existence oracle** intact through the toolset (tests 4, 5).
4. **One audit record per authorized call**, none for a rejected one (tests 7, 9).
5. **Zero blast radius** — only `agents/functions.py` rewritten, `test_stubs.py` trimmed, `test_agent_tools.py` added; `authz`/`ResearchService`/routes/schema untouched.
