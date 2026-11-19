# Agent tool functions (permission checks outside the LLM) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the three `agents/functions.py` stubs with a role-bound `AgentToolset` that enforces the caller's permissions in application code — the model may *request* a tool with data arguments only, and can never change its own role or slip a malformed argument past to the service.

**Architecture:** `AgentToolset(service, *, role)` binds a verified role at construction (trusted code, not the model). Its three tools — `search_cve`, `search_attack`, `search_research` — validate their argument shape, then delegate to the existing `ResearchService` authorize-before-retrieve methods, returning the cited `ResearchResult`. No new route, no LLM, no change to any other module.

**Tech Stack:** Python 3.12, stdlib only at runtime, no new dependency.

**Spec:** `docs/superpowers/specs/2026-11-19-phase3-agent-tools-design.md`

## Global Constraints

- stdlib-only at runtime, no new dependency. Deterministic, offline, hermetic (no `@pytest.mark.integration`). PUBLIC/synthetic only.
- **Do NOT modify** `authz`, `ResearchService`, the loaders, the routes, `deps`, or the schema. Only `agents/functions.py` is rewritten; `tests/test_stubs.py` is trimmed; `tests/test_agent_tools.py` is added.
- The role is bound at construction and immutable — no tool method takes or honors a role argument.
- Argument validation precedes any service call: a malformed `cve_id`/`technique_id`/`query` raises `ValueError` (name the argument, never echo the raw value) before any retrieval or audit.
- `ruff`/`black`/`mypy` clean, line length 100. Every commit ends with the attribution footer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU`.

## Review Focus

1. **Principal unforgeable from the model side** — no tool method accepts/honors a role argument; the bound role is the only one used — Task 1 `test_role_is_bound_not_a_tool_argument`.
2. **Fail-closed on bad input** — a malformed/hostile argument never reaches the service, never retrieves, never audits; the error message doesn't echo the payload — Task 1 `test_malformed_*`.
3. **Deny-by-default + no existence oracle** through the toolset — Task 1 `test_unauthorized_role_*`.
4. **Exactly one audit record per authorized call; none for a rejected one** — Task 1 `test_authorized_call_emits_exactly_one_audit_record` + the zero-record assertion in `test_malformed_cve_id_raises_before_retrieval`.
5. **Zero blast radius** — only `agents/functions.py`, `test_stubs.py`, `test_agent_tools.py` in the diff — final review.

---

### Task 1: `AgentToolset` + tests (retire the three stubs)

**Files:**
- Rewrite: `src/secure_ai_research/agents/functions.py`
- Test: `tests/test_agent_tools.py` (create)
- Modify: `tests/test_stubs.py` (remove the three `functions.search_*` entries + the now-unused import)

**Interfaces:**
- Consumes (existing, unchanged): `ResearchService(embedder, store, authorize, audit_path)` with `.research_cve(cve_id, *, role)`, `.research_attack(technique_id, *, role)`, `.search(query, *, role, limit=5)`, all returning `ResearchResult(outcome, answer, citations, research_id)`; `Outcome` (OK/DENIED/NOT_FOUND); `authorize`; `HashingEmbedder`; `InMemoryVectorStore`; `read_records(path)`; `ResearchDocument`/`IngestedDocument`/`DocumentType`/`Classification` for the test corpus.
- Produces: `AgentToolset` with `__init__(self, service: ResearchService, *, role: str)`, `search_cve(self, cve_id: str) -> ResearchResult`, `search_attack(self, technique_id: str) -> ResearchResult`, `search_research(self, query: str) -> ResearchResult`.

- [ ] **Step 1: Write the failing tests** `tests/test_agent_tools.py`

Helper builds a hermetic service on a temp audit log with a tiny synthetic corpus (one PUBLIC CVE doc whose text contains "CVE-2021-44228 log4j", one PUBLIC ATT&CK doc id `T1059` whose text contains "T1059 command interpreter"), then the nine cases from design §7.2. Pin the helper shape and the two load-bearing security tests as code; the rest follow their §7.2 descriptions in the same style:

```python
import inspect
import pytest
from secure_ai_research.agents.functions import AgentToolset
from secure_ai_research.audit.record import read_records
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import Classification, DocumentType, ResearchDocument
from secure_ai_research.research_service import Outcome, ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore

_HASH = "sha256:" + "0" * 64

def _doc(doc_id, text, dtype):
    d = ResearchDocument(
        document_id=doc_id, source="test", document_type=dtype,
        classification=Classification.PUBLIC, created_at="2021-12-10",
        source_url="https://example.test/x", integrity_hash=_HASH,
    )
    return IngestedDocument(document=d, text=text)

def _service(tmp_path):
    svc = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, tmp_path / "audit.jsonl")
    svc.index([
        _doc("CVE-2021-44228", "CVE-2021-44228 log4j remote code execution", DocumentType.VULNERABILITY),
        _doc("T1059", "T1059 command and scripting interpreter", DocumentType.TECHNIQUE),
    ])
    return svc

def test_role_is_bound_not_a_tool_argument(tmp_path):
    svc = _service(tmp_path)
    analyst = AgentToolset(svc, role="research_analyst")
    auditor = AgentToolset(svc, role="security_auditor")
    assert analyst.search_cve("CVE-2021-44228").outcome is Outcome.OK
    assert auditor.search_cve("CVE-2021-44228").outcome is Outcome.DENIED
    assert "role" not in inspect.signature(AgentToolset.search_cve).parameters

def test_malformed_cve_id_raises_before_retrieval(tmp_path):
    svc = _service(tmp_path)
    tools = AgentToolset(svc, role="research_analyst")
    with pytest.raises(ValueError):
        tools.search_cve("DROP TABLE docs")
    assert read_records(tmp_path / "audit.jsonl") == []  # validation precedes the service
```

Remaining cases (design §7.2), each its own test: `search_cve/attack/research` authorized → OK with citations (1–3); unauthorized `security_auditor` → DENIED + empty citations for all three tools (4); unauthorized role, real vs fake CVE id both DENIED-identical (5); malformed `technique_id`, empty-after-strip `query`, and >512-char `query` each raise `ValueError` with zero audit records (7); the `ValueError` for a hostile query does not contain the payload substring (8); one authorized `search_cve` → exactly one `read_records` entry (9).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_agent_tools.py -q`
Expected: FAIL at import — `cannot import name 'AgentToolset' from secure_ai_research.agents.functions`.

- [ ] **Step 3: Rewrite `src/secure_ai_research/agents/functions.py`**

Per design §7.1: module docstring restating the enforced rule + pointing at `roles.md`; `import re`; `from secure_ai_research.research_service import ResearchResult, ResearchService`; module constants `_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")`, `_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")`, `_QUERY_MAX = 512`; the `AgentToolset` class. Each tool: validate (raise `ValueError("search_cve: cve_id is not a valid CVE identifier")` style — name the arg, no payload echo), then `return self._service.research_cve(cve_id, role=self._role)` (resp. `research_attack`, `search`). `search_research` strips the query, checks `1 <= len <= _QUERY_MAX`, passes the stripped query. No `role` parameter on any method; no limit parameter on `search_research`. Remove the three old stub functions.

- [ ] **Step 4: Trim `tests/test_stubs.py`**

Remove the three `(functions.search_*, …)` tuples from `STUB_CALLS` and the `from secure_ai_research.agents import functions` import (now unused). Keep `metrics.score` and `test_adapter_stubs_raise_on_construction`.

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `.venv/bin/pytest tests/test_agent_tools.py -q`
Expected: PASS (all nine).

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: green (confirms `test_stubs.py` still collects + passes after the trim). Record the count.

- [ ] **Step 7: Lint + commit**

Run: `.venv/bin/ruff check . && .venv/bin/black --check . && .venv/bin/mypy`
Expected: clean.
```bash
git add src/secure_ai_research/agents/functions.py tests/test_agent_tools.py tests/test_stubs.py
git commit   # feat(agents): role-bound AgentToolset — permission checks outside the LLM  (+ footer)
```

---

## Final checks (before review)

- [ ] `.venv/bin/pytest -q` — full suite green (hermetic).
- [ ] `.venv/bin/ruff check . && .venv/bin/black --check . && .venv/bin/mypy` — clean.
- [ ] `git diff --stat main..HEAD` — only `agents/functions.py`, `test_agent_tools.py`, `test_stubs.py`, plus the design + this plan.
