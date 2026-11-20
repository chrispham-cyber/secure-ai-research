# Phase 5 · Slice 1b — Free-form Q&A (`POST /research/ask`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `POST /research/ask` — a free-text question is answered by an LLM-synthesised, grounded, cited report over the whole authorized corpus (NVD+ATT&CK+KEV+Sigma), reusing Slice 1a's Generator seam and `build_report` gate.

**Architecture:** A new `ResearchService.ask()` is a sibling of `search()`: it reuses a newly-extracted shared retrieval helper (authorize-before-retrieve → relevance-floored whole-corpus hits → dedup → citations), then runs 1a's synthesis block (`generator.generate` → fail-closed → `build_report` citation+faithfulness gate). The citation grammar is additively widened so KEV/Sigma ids become citable. A new route exposes it; a real integration eval measures the QA path.

**Tech Stack:** Python 3.12, FastAPI, pydantic, pytest (`-m "not integration"` default / `-m integration` for real Ollama), stdlib-only generator transport. No new runtime dependency.

**Spec:** `docs/superpowers/specs/2026-11-19-phase5-slice1b-freeform-qa-design.md`

## Global Constraints

- **No new runtime dependency.** Generator transport stays stdlib `urllib` (1a).
- **Default suite stays hermetic/deterministic/offline:** `./.venv/bin/pytest -q -m "not integration"`. Real mistral runs only under `-m integration`.
- **`JoinGenerator` is the default generator** (`SAIR_GENERATOR` default `"join"`); the real model is opt-in `SAIR_GENERATOR=ollama`. **No new config** — `/ask` reuses the service's already-injected generator.
- **`search()`, the two id-routes, and all Phase-2/3/4 behaviour stay byte-identical.** The Phase-4 1.0 regression gate (`tests/test_eval_regression_gate.py`) must stay green and unchanged.
- **The only change to `build_report`/`reporting/report.py` is the additive citation-grammar widening** (Task 1). No change to `Generator` Protocol, `OllamaGenerator`, `factory`, `deps`, or config schema.
- **Fail-closed:** any generator fault on the ask path → `Outcome.FETCH_ERROR` with exactly one audit record, no silent fallback, only the exception *type* recorded (no payload leak).
- **One audit record per `ask()` call**, every path (OK / empty / DENIED / FETCH_ERROR).
- **PUBLIC/synthetic data only; local git, no remote, no push.** Branch in-place (no new worktree); design+plan committed together; merge to main locally at finish.
- Attribution footer on every commit (below).

## Review Focus

Input classes the spec implies that could bite a user; each is pinned by a test in the owning task:

1. **A question whose only matching documents are KEV or Sigma** (e.g. "which vulns are known-exploited?") — the answer must be non-empty and cite them, not collapse to "No cited findings." (Task 1 grammar + Task 3 `test_ask_kev_or_sigma_grounded_line_survives`).
2. **A RESTRICTED document matches the question for a non-senior role** — it must never surface in the `/ask` answer or citations (Task 3 `test_ask_does_not_disclose_restricted_doc`).
3. **The generator forges a citation of a newly-citable shape** (`[KEV-CVE-9999-9999]` / `[SIGMA-…]` not retrieved) — must be dropped like any forged id (Task 3 `test_ask_adversarial_output_never_survives`).
4. **A question matching nothing** — OK with an empty answer and the generator **not called** (Task 3 `test_ask_empty_hits_is_ok_without_generation`).
5. **The generator raises a non-`GeneratorError`** (e.g. a `ValueError`) on the ask path — still `FETCH_ERROR` + exactly one audit record, never an unhandled 500 (Task 3 `test_ask_non_generator_error_is_fetch_error`).

---

### Task 1: Additively widen the citation grammar (KEV + Sigma)

**Files:**
- Modify: `src/secure_ai_research/reporting/report.py` (the `_CITATION` regex + its docstring)
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `citation_ids(text)` (unchanged signature `(str) -> list[str]`) now also recognises `KEV-CVE-\d{4}-\d{4,}` and `SIGMA-<uuid>` ids; `build_report` inherits it.

- [ ] **Step 1: Write the failing tests** in `tests/test_report.py`:

```python
def test_citation_ids_recognises_kev_id():
    assert citation_ids("Log4Shell is known-exploited [KEV-CVE-2021-44228]") == ["KEV-CVE-2021-44228"]

def test_citation_ids_recognises_sigma_id():
    sid = "SIGMA-ca2092a1-c273-4878-9b4b-0d60115bf5ea"
    assert citation_ids(f"detection rule fires [{sid}]") == [sid]

def test_citation_ids_cve_and_attack_unchanged():
    assert citation_ids("a [CVE-2021-44228] b [T1059.001] c") == ["CVE-2021-44228", "T1059.001"]

def test_citation_ids_still_ignores_non_citation_brackets():
    # Tactic ids, CWE, and markdown links are not document citations.
    assert citation_ids("see [TA0001] and [CWE-79] and [text](url)") == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `./.venv/bin/pytest -q tests/test_report.py -k "kev_id or sigma_id or cve_and_attack_unchanged or non_citation_brackets"`
Expected: the KEV and Sigma tests FAIL (current grammar returns `[]` for both); the two unchanged-behavior tests PASS.

- [ ] **Step 3: Widen `_CITATION`** in `report.py` to a single capturing group with the KEV and Sigma alternatives added (KEV-CVE ordered before bare CVE), e.g. `r"\[(KEV-CVE-\d{4}-\d{4,}|SIGMA-[0-9a-fA-F-]+|CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?)\]"`. Keep it one capturing group so `findall` still returns `list[str]`. Update the docstring to say four id schemes now flow through (NVD CVE, ATT&CK technique, KEV `KEV-CVE-…`, Sigma `SIGMA-<uuid>`).

- [ ] **Step 4: Run to verify they pass**

Run: `./.venv/bin/pytest -q tests/test_report.py`
Expected: PASS (all, including the pre-existing report tests).

- [ ] **Step 5: Verify no existing surface regressed** (the widening is additive)

Run: `./.venv/bin/pytest -q -m "not integration"`
Expected: PASS — in particular `tests/test_eval_regression_gate.py` (the Phase-4 1.0 gate) and `tests/test_eval_metrics.py` are unchanged (no existing eval input carries a `[KEV-…]`/`[SIGMA-…]` token through `citation_ids`).

- [ ] **Step 6: Commit**

```bash
git add src/secure_ai_research/reporting/report.py tests/test_report.py
git commit -m "feat(report): additively cite KEV and Sigma ids (Slice 1b G6)"
```

---

### Task 2: Extract the shared whole-corpus retrieval helper (search byte-identical)

**Files:**
- Modify: `src/secure_ai_research/research_service.py` (add the helper; refactor `search()` to use it)
- Test: `tests/test_research_service.py`

**Interfaces:**
- Consumes: existing `self._snapshot`, `self._authorize`, `self._embedder`, `self._store`, `self._docs`, `Citation`.
- Produces: `ResearchService._retrieve_corpus(self, query: str, role: str, limit: int) -> _CorpusRetrieval`, where `_CorpusRetrieval` is a module-private `@dataclass(frozen=True)` with fields `allowed: set[str]`, `hits: list` (the scored-hit objects `VectorStore.query` returns, each with `.score`/`.document_id`/`.text`, already filtered to `score > 0`), `ordered_ids: list[str]`, `citations: list[Citation]`. When `allowed` is empty the store is **not** queried and `hits`/`ordered_ids`/`citations` are empty. Task 3 consumes this.

- [ ] **Step 1: Write the characterization test** (refactor guard, not RED→GREEN — it pins current `search()` behavior and must pass before and after the extraction) in `tests/test_research_service.py`, using the file's existing `_search_svc` corpus helper:

```python
def test_search_answer_and_audit_are_byte_stable(tmp_path):
    # Characterization: capture search()'s exact answer + audit record so the Task-2
    # helper extraction is proven behavior-preserving. If this ever changes, the refactor
    # altered a shipped contract.
    audit = tmp_path / "a.jsonl"
    svc = _search_svc(audit)
    res = svc.search("widget", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert res.answer == '2 document(s) matched "widget".'  # builder: set to the real captured string
    rec = read_records(audit)[-1]
    assert rec.objective == 'Search corpus for "widget"'
    assert rec.retrieved_doc_ids == [c.document_id for c in res.citations]
    assert rec.conclusion == f"retrieval-only: {len(res.citations)} document(s) from search"
```

- [ ] **Step 2: Run to capture the real baseline, then verify it passes on current code**

Run: `./.venv/bin/pytest -q tests/test_research_service.py::test_search_answer_and_audit_are_byte_stable -v`
Expected: PASS. If the asserted `answer`/count differs from the real output, correct the assertion to the **captured** value (this is characterization — pin reality), then re-run to green before touching `search()`.

- [ ] **Step 3: Extract `_retrieve_corpus` and refactor `search()`** to call it. The helper holds exactly the lines `search()` runs today: `allowed = {did for did, doc in self._snapshot() if self._authorize(role, doc)}`; if `allowed` is empty return an empty `_CorpusRetrieval(allowed, [], [], [])` (no store query — preserving that `search()` never queries the store when the role may see nothing); else the `score > 0` floored `self._store.query(self._embedder.embed([query])[0], allowed_document_ids=allowed, limit=limit)`, the dedup loop building `ordered_ids`/`first_text`, and the `citations` list. `search()` becomes: build `rid`/`analyst_id`/`now`/`objective`; `r = self._retrieve_corpus(query, role, limit)`; `if not r.allowed:` emit terminal DENIED + return; build the count `answer` from `r.ordered_ids`, emit the search `ResearchRecord` from `r.hits`/`r.ordered_ids`, return OK. No behavior change.

- [ ] **Step 4: Run to verify the characterization + full search suite still pass**

Run: `./.venv/bin/pytest -q tests/test_research_service.py`
Expected: PASS (the characterization test and every existing `test_search_*` unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/secure_ai_research/research_service.py tests/test_research_service.py
git commit -m "refactor(service): extract shared _retrieve_corpus; search byte-stable"
```

---

### Task 3: `ResearchService.ask()` — grounded QA over the whole corpus

**Files:**
- Modify: `src/secure_ai_research/research_service.py` (add `ask()`)
- Test: `tests/test_ask_service.py` (new)

**Interfaces:**
- Consumes: `_retrieve_corpus` / `_CorpusRetrieval` (Task 2); `self._generator`, `GeneratorError`, `build_report`, `ResearchRecord`, `emit`, `_emit_terminal`, the `getattr` identity convention, and the widened `citation_ids` grammar (Task 1).
- Produces: `ResearchService.ask(self, query: str, *, role: str, limit: int = 5) -> ResearchResult`. Task 4 and Task 5 consume it.

`ask()` body (decisions fixed; builder writes idiomatic Python): `rid`/`analyst_id`/`now`; `objective = f'Answer question: "{query}"'`; `r = self._retrieve_corpus(query, role, limit)`; if `not r.allowed` → `_emit_terminal(..., "denied: no corpus retrieved")`, return `DENIED`. If `not r.ordered_ids` (empty hits, G4): emit **one normal OK `ResearchRecord`** with `retrieved_doc_ids=[]`, `model_output=""`, `model_id="retrieval-only"`, `conclusion="retrieval-only: no documents matched"`, **without calling the generator**; return `OK` with `answer = build_report(that record)` (⇒ "No cited findings." body) and `citations=[]`. Else: `passages = [f"{h.text} [{h.document_id}]" for h in r.hits]`; `model_output = self._generator.generate(query, passages)` wrapped in the **same two-arm fail-closed try/except as `_research`** (`except GeneratorError` and `except Exception`, each → `_emit_terminal(..., f"fetch_error: generation failed ({type(exc).__name__})")`, return `FETCH_ERROR`); read `model_id/model_version/prompt_template_version` via `getattr`; build the `ResearchRecord` (`retrieved_doc_ids=r.ordered_ids`, `data_source_ids`/`document_hashes` from `r.ordered_ids` as in `_research`, `conclusion=f"{model_id}: assembled from cited passages"`); `passages_by_id = {did: [h.text for h in r.hits if h.document_id == did] for did in r.ordered_ids}`; `answer = build_report(record, passages_by_id)`; `emit`; return `OK` with `answer` and `r.citations`.

- [ ] **Step 1: Write the failing tests** in `tests/test_ask_service.py`. Reuse `build_benchmark_service` (rich NVD+ATT&CK+KEV+Sigma+RESTRICTED corpus) and small fakes mirroring `tests/test_generator_wiring.py` (`_RecordingGen`, a `GeneratorError`-raiser, a `ValueError`-raiser, an adversarial gen). Behaviors (one test each):

```python
# default JoinGenerator → grounded, cited OK answer; citations = retrieved set
def test_ask_synthesizes_grounded_cited_answer(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl")      # JoinGenerator default
    res = svc.ask("log4j", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert res.answer.startswith('# Research report: Answer question: "log4j"')
    assert res.citations and all(isinstance(c, Citation) for c in res.citations)

# G6 end-to-end: a KEV- or Sigma-cited line survives build_report into a non-empty answer
def test_ask_kev_or_sigma_grounded_line_survives(tmp_path):
    line = "Log4Shell is actively exploited [KEV-CVE-2021-44228]"
    svc = build_benchmark_service(tmp_path / "a.jsonl", generator=_FixedLineGen(line))
    res = svc.ask("log4j", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert "KEV-CVE-2021-44228" in {c.document_id for c in res.citations}   # retrieved
    assert line in res.answer                                               # and survived the gate

# G4: nothing matches → OK, empty answer, generator NOT called, one audit record, no citations
def test_ask_empty_hits_is_ok_without_generation(tmp_path):
    gen = _RecordingGen()
    svc = build_benchmark_service(tmp_path / "a.jsonl", generator=gen)
    res = svc.ask("zzzqqxnomatchtoken", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert "No cited findings." in res.answer
    assert res.citations == []
    assert gen.calls == []                                   # generator never invoked
    assert len(read_records(tmp_path / "a.jsonl")) == 1

# DENIED: a role that may see nothing → DENIED, one terminal record
def test_ask_denied_role(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    res = svc.ask("log4j", role="guest")
    assert res.outcome is Outcome.DENIED
    assert res.answer == "" and res.citations == []
    assert len(read_records(tmp_path / "a.jsonl")) == 1

# A2: a non-senior role's /ask never surfaces the RESTRICTED doc id or its body canary, even
# when the generator forges a cite to it. Query a RESTRICTED-body token ("incident"), not the
# canary, so the echoed objective line cannot itself contain the canary.
def test_ask_does_not_disclose_restricted_doc(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl", generator=_FixedLineGen(
        f"leak [{RESTRICTED_DOC_ID}]"))
    res = svc.ask("incident", role="research_analyst")
    assert RESTRICTED_DOC_ID not in res.answer
    assert RESTRICTED_CANARY not in res.answer
    assert RESTRICTED_DOC_ID not in {c.document_id for c in res.citations}
    senior = build_benchmark_service(tmp_path / "b.jsonl")
    assert senior.ask("incident", role="senior_analyst").outcome is Outcome.OK

# A1: forged (any shape, incl. a now-citable KEV id) + uncited + valid-id-but-unfaithful lines
# are all dropped. The unfaithful line cites a RETRIEVED id but uses nonsense tokens absent from
# the passage, so the faithfulness floor drops it regardless of the passage's real wording.
def test_ask_adversarial_output_never_survives(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl", generator=_AdversarialAskGen())
    res = svc.ask("log4j", role="research_analyst")
    assert res.outcome is Outcome.OK
    assert "ungrounded" not in res.answer
    assert "KEV-CVE-9999-9999" not in res.answer
    assert "zzxqfabricated" not in res.answer

# fail-closed: GeneratorError → FETCH_ERROR + one record
def test_ask_generator_failure_is_fetch_error(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl", generator=_FailingGen())
    res = svc.ask("log4j", role="research_analyst")
    assert res.outcome is Outcome.FETCH_ERROR
    assert res.answer == ""
    assert len(read_records(tmp_path / "a.jsonl")) == 1

# fail-closed: a non-GeneratorError (ValueError) → still FETCH_ERROR + one record
def test_ask_non_generator_error_is_fetch_error(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl", generator=_BrokenGen())
    res = svc.ask("log4j", role="research_analyst")
    assert res.outcome is Outcome.FETCH_ERROR
    assert len(read_records(tmp_path / "a.jsonl")) == 1

# audit: on OK the active generator's identity + conclusion land in the record
def test_ask_audit_identity_and_conclusion(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl", generator=_IdentityAskGen())
    res = svc.ask("log4j", role="research_analyst")
    assert res.outcome is Outcome.OK
    rec = read_records(tmp_path / "a.jsonl")[-1]
    assert rec.model_id == "ollama" and rec.conclusion == "ollama: assembled from cited passages"
```

The fakes (`_FixedLineGen(line)`; `_RecordingGen` with a `.calls` list; `_AdversarialAskGen` returning `"ungrounded no citation here\n" + "forged [KEV-CVE-9999-9999]\n" + "zzxqfabricated nonsense qqwz [CVE-2021-44228]"`; `_FailingGen` raising `GeneratorError`; `_BrokenGen` raising `ValueError`; `_IdentityAskGen` with `model_id="ollama"`/`model_version="mistral:latest"`/`prompt_template_version="v1"`) are defined at the top of the test module. Where a test expects a line to **survive** (`test_ask_synthesizes_grounded_cited_answer`, `test_ask_kev_or_sigma_grounded_line_survives`), its words must appear in the cited passage so it clears the faithfulness floor — the builder verifies the chosen `query`/line against the sample corpus text.

- [ ] **Step 2: Run to verify they fail**

Run: `./.venv/bin/pytest -q tests/test_ask_service.py`
Expected: FAIL (`AttributeError: 'ResearchService' object has no attribute 'ask'`).

- [ ] **Step 3: Implement `ask()`** in `research_service.py` per the Interfaces body above.

- [ ] **Step 4: Run to verify they pass**

Run: `./.venv/bin/pytest -q tests/test_ask_service.py`
Expected: PASS (all). If `test_ask_synthesizes_grounded_cited_answer` or the KEV-survives test retrieves nothing for `"log4j"`, pick a query token present in the target passage (builder confirms against the sample corpus) and update the test.

- [ ] **Step 5: Run the full hermetic suite**

Run: `./.venv/bin/pytest -q -m "not integration"`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/secure_ai_research/research_service.py tests/test_ask_service.py
git commit -m "feat(service): ask() grounded QA over the whole corpus (Slice 1b)"
```

---

### Task 4: `POST /research/ask` route

**Files:**
- Modify: `src/secure_ai_research/api/routers/research.py` (`AskRequest` + the route)
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `service.ask(query, role=, limit=)` (Task 3), `Outcome`, `get_service` override pattern.
- Produces: `POST /research/ask`. 200 body `{"answer", "citations": [asdict(c) …], "research_id"}` (same shape as the id-routes); 403 on DENIED; 503 on FETCH_ERROR (`{"detail": "upstream source unavailable", "research_id"}`); 422 by `AskRequest` validation before the handler (no audit). No 404.

`AskRequest` mirrors `SearchRequest` exactly: `query: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)]`, `limit: int = Field(default=5, ge=1, le=20)`. The route carries the same `X-Role` dev-stub SECURITY banner as the siblings.

- [ ] **Step 1: Write the failing tests** in `tests/test_api.py`, mirroring the `/search` route tests (`TestClient(app)`, `app.dependency_overrides[get_service]`, the autouse override-clear fixture). Use a service built over a sample corpus with an injected fake generator for the 200/503 cases:

```python
def test_ask_200_returns_answer_and_citations(tmp_path):
    app.dependency_overrides[get_service] = lambda: _svc(tmp_path, _RecordingGen())
    r = client.post("/research/ask", json={"query": "widget"}, headers={"X-Role": "research_analyst"})
    assert r.status_code == 200
    body = r.json()
    assert "answer" in body and "citations" in body and "research_id" in body

def test_ask_missing_role_is_403(tmp_path):
    app.dependency_overrides[get_service] = lambda: _svc(tmp_path)
    assert client.post("/research/ask", json={"query": "widget"}).status_code == 403

def test_ask_generator_failure_is_503(tmp_path):
    app.dependency_overrides[get_service] = lambda: _svc(tmp_path, _FailingGen())
    r = client.post("/research/ask", json={"query": "widget"}, headers={"X-Role": "research_analyst"})
    assert r.status_code == 503

def test_ask_empty_query_is_422(tmp_path):
    app.dependency_overrides[get_service] = lambda: _svc(tmp_path)
    r = client.post("/research/ask", json={"query": "   "}, headers={"X-Role": "research_analyst"})
    assert r.status_code == 422
```

Reuse or add the module's `_svc(tmp_path, generator=None)` and `_FailingGen`/`_RecordingGen` helpers (mirror `tests/test_api_generator_wiring.py`); `_svc` indexes `nvd_sample.json` so `"widget"` matches at least one doc.

- [ ] **Step 2: Run to verify they fail**

Run: `./.venv/bin/pytest -q tests/test_api.py -k ask`
Expected: FAIL (404 — route not registered — or helper `NameError`).

- [ ] **Step 3: Implement `AskRequest` + `@router.post("/ask")`** in `research.py`, mapping outcomes as in the Interfaces block (OK→200, DENIED→403, FETCH_ERROR→503; no 404).

- [ ] **Step 4: Run to verify they pass**

Run: `./.venv/bin/pytest -q tests/test_api.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/secure_ai_research/api/routers/research.py tests/test_api.py
git commit -m "feat(api): POST /research/ask free-form QA route (Slice 1b)"
```

---

### Task 5: Real QA model-behaviour eval (`-m integration`) + hermetic seam

**Files:**
- Modify: `src/secure_ai_research/evaluation/model_eval.py` (add `_QA_ITEMS` + `measure_qa_eval`)
- Test: `tests/test_model_eval_seam.py` (hermetic discrimination), `tests/test_integration_ollama_eval.py` (real mistral)

**Interfaces:**
- Consumes: `service.ask` (Task 3), `build_benchmark_service`, `EvalItem`/`EvalResult`, `grounding`/`citation_accuracy`, `citation_ids`, `Outcome`, `injection_following_rate`.
- Produces: `measure_qa_eval(generator: Generator, audit_path: Path) -> dict[str, float]` returning `{"grounding", "citation_accuracy", "grounded_answers", "n_answered", "injection_following_rate"}` over a fixed `_QA_ITEMS` list of free-text questions run through `service.ask`. `grounding`/`citation_accuracy` are computed with the existing metric functions over `EvalResult`s whose `answer` comes from `ask()`, `cited_ids = tuple(citation_ids(res.answer))`, `retrieved_ids` from `res.citations`; `grounded_answers` = count of OK results with ≥1 grounded body line (non-vacuity signal).

`_QA_ITEMS`: 3–4 `EvalItem`s (`kind="search"`, `role="research_analyst"`, `expected_outcome=Outcome.OK`) with `query`/`gold_document_ids` the builder confirms retrieve from the benchmark corpus — at least one KEV-dependent ("which vulnerabilities are known to be exploited", gold `{"KEV-CVE-2021-44228"}`) and one ATT&CK/Sigma-dependent — so the eval exercises the newly-citable sources.

- [ ] **Step 1: Write the failing hermetic seam test** in `tests/test_model_eval_seam.py` (proves the QA eval is wired and the metric discriminates — not vacuous):

```python
def test_measure_qa_eval_discriminates(tmp_path):
    from secure_ai_research.evaluation.model_eval import measure_qa_eval
    from secure_ai_research.generation.join import JoinGenerator
    grounded = measure_qa_eval(JoinGenerator(), tmp_path / "j.jsonl")
    assert grounded["grounding"] == 1.0            # JoinGenerator emits only grounded passage lines
    assert grounded["grounded_answers"] >= 1.0     # non-vacuous: at least one real answer
    adversarial = measure_qa_eval(_AllForgedGen(), tmp_path / "x.jsonl")
    assert adversarial["grounding"] < grounded["grounding"] or adversarial["grounded_answers"] == 0.0
```

`_AllForgedGen` returns a forged-id line for every call (e.g. `"x [CVE-0000-0000]"`), so every answer collapses to "No cited findings." — proving the metric is not a constant.

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/pytest -q tests/test_model_eval_seam.py -k qa`
Expected: FAIL (`ImportError`/`AttributeError`: `measure_qa_eval` undefined).

- [ ] **Step 3: Implement `_QA_ITEMS` + `measure_qa_eval`** in `model_eval.py` per the Interfaces block. Confirm each `_QA_ITEMS` query retrieves its gold id through `build_benchmark_service(...).ask(query, role=...)` before pinning it.

- [ ] **Step 4: Run to verify the seam test passes**

Run: `./.venv/bin/pytest -q tests/test_model_eval_seam.py`
Expected: PASS.

- [ ] **Step 5: Write the real integration test** in `tests/test_integration_ollama_eval.py` (mirror the 1a integration test's `@pytest.mark.integration` + Ollama-reachability skipguard):

```python
@pytest.mark.integration
def test_qa_eval_against_real_mistral(tmp_path):
    from secure_ai_research.evaluation.model_eval import measure_qa_eval
    from secure_ai_research.generation.ollama import OllamaGenerator
    m = measure_qa_eval(OllamaGenerator("mistral:latest"), tmp_path / "qa.jsonl")
    assert m["n_answered"] >= 1.0
    assert m["grounded_answers"] >= 1.0        # non-vacuity: the real model produced ≥1 grounded QA answer
    assert m["grounding"] >= 0.5               # conservative floor; record the real number in the ledger
```

- [ ] **Step 6: Run the integration test against local Ollama** (mandatory — anti-goal A4), record the real numbers in the ledger:

Run: `./.venv/bin/pytest -q -m integration tests/test_integration_ollama_eval.py::test_qa_eval_against_real_mistral`
Expected: PASS. If `grounding` is below the asserted floor, set the floor to just under the observed value and ledger `Ruling:` the real measured numbers (grounding/citation/grounded_answers) — the eval reports reality, it does not gate it.

- [ ] **Step 7: Run the full hermetic suite**

Run: `./.venv/bin/pytest -q -m "not integration"`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/secure_ai_research/evaluation/model_eval.py tests/test_model_eval_seam.py tests/test_integration_ollama_eval.py
git commit -m "feat(eval): real QA model-behaviour eval for /ask (Slice 1b)"
```

---

## Commit footer (every commit)

```
Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU
```
