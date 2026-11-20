# Phase 5 · Slice 1a — Real Generator + grounded synthesis — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put a real local LLM (Ollama/mistral) behind the existing `Generator` seam so the CVE/ATT&CK id-routes return grounded, faithful, natural-language answers — default path byte-identical to today, real behaviour measured behind `-m integration`.

**Architecture:** Introduce `Generator` at the single id-route seam in `ResearchService` (`research_service.py:205`). The default is a deterministic `JoinGenerator` (output == today's string-join), so the hermetic suite, the 1.0 CI gate, and the audit log stay byte-identical; a configured `OllamaGenerator` swaps in. `build_report` keeps dropping uncited/wrong-id lines and additionally drops **unfaithful** lines (a lenient token-overlap floor vs. the cited passages). A real integration eval runs the Phase-4 benchmark + injection corpus through the live model and reports measured numbers.

**Tech Stack:** Python 3.12, pydantic/pydantic-settings, FastAPI, stdlib `urllib.request` (no new runtime dep), pytest. Ollama `mistral:latest` for the integration eval only.

**Spec:** `docs/superpowers/specs/2026-11-19-phase5-slice1a-generator-synthesis-design.md`

## Global Constraints

- **Byte-identity of the default path (G3):** with the default (`JoinGenerator`) generator, every endpoint's answer **and** its audit `ResearchRecord` are byte-identical to pre-change output. The deterministic benchmark + `tests/test_eval_regression_gate.py` 1.0 gate must stay green and unchanged.
- **Posture (§5):** real services only under `pytest -m integration`; the default `pytest -m "not integration"` suite stays hermetic/offline/deterministic. No live Ollama in any default-suite test.
- **No new runtime dependency:** Ollama HTTP via stdlib `urllib.request`, keyless localhost, explicit timeout.
- **Protocol unchanged:** `Generator.generate(prompt: str, passages: Sequence[str]) -> str` (generation/ports.py) is not modified; the Week-16 fakes must still satisfy `isinstance(_, Generator)`. Generator *identity* (`model_id`/`model_version`/`prompt_template_version`) is a plain attribute convention on the concrete generators, read by the service via `getattr(..., default)`, **not** added to the Protocol.
- **Audit honesty (§10 Q2):** the id-route record's `model_id`/`model_version`/`prompt_template_version` and the `conclusion` prefix come from the active generator. `JoinGenerator` reports `("retrieval-only", "", "")` ⇒ default record byte-identical; `OllamaGenerator` names the model.
- **Generator failure never degrades silently (§10 Q1):** an `OllamaGenerator` failure raises `GeneratorError`; the service maps it to `Outcome.FETCH_ERROR` with one audit record. Never fall back to `JoinGenerator`, never fabricate findings.
- **Generator runs only on the id-route, only with hits:** the search path (`:306`) and all terminal paths (DENIED/NOT_FOUND/FETCH_ERROR) keep deterministic `model_output` and `model_id="retrieval-only"` — they perform no generation. (Ledgered narrowing of the design's "two sites": search `model_output` is audit-only, never surfaced or evaluated, so an LLM call there buys nothing.)
- **Test commands:** default `./.venv/bin/pytest -q -m "not integration"`; integration `./.venv/bin/pytest -q -m integration`. Local git, no remote — no push.

## Review Focus

- **RF1 — Ollama returns HTTP 200 with an empty/whitespace `response`.** `OllamaGenerator.generate` must raise `GeneratorError`, not return `""` (which would silently become "No cited findings"). *(Task 2)*
- **RF2 — the model emits text with no citations or malformed citations.** `build_report` drops every such line and yields the literal `No cited findings.` body — no crash, no uncited claim shown. *(Task 3)*
- **RF3 — a generated line cites a genuinely-retrieved id but with invented text** (anti-goal A1): the faithfulness floor drops it; it reaches neither the answer nor the grounding score. *(Task 3)*
- **RF4 — the default (`JoinGenerator`) audit record changes.** A regression in `model_id`/`conclusion`/`model_output` silently rewrites the audit trail; a characterization test pins the exact record for a known query. *(Task 1)*
- **RF5 — the integration eval runs with Ollama unreachable.** It must `skip` with a clear reason (CI/offline stays green), never fail and never report a vacuous "measured" pass. *(Task 5)*

---

### Task 1: `JoinGenerator` + wire `Generator` into the id-route (byte-identical, incl. audit identity)

**Files:**
- Create: `src/secure_ai_research/generation/join.py`
- Modify: `src/secure_ai_research/research_service.py` (`__init__`; `_research` ~205–223)
- Test: `tests/test_generator_wiring.py`

**Interfaces:**
- Consumes: `Generator` Protocol (`generation/ports.py`), `ResearchRecord`/`emit`, `build_report`.
- Produces:
  - `JoinGenerator` — `generate(self, prompt: str, passages: Sequence[str]) -> str` returns `"\n".join(passages)`; class attrs `model_id = "retrieval-only"`, `model_version = ""`, `prompt_template_version = ""`.
  - `ResearchService.__init__(self, embedder, store, authorize, audit_path, limit=5, *, fetch_missing=None, generator: Generator | None = None)` storing `self._generator = generator or JoinGenerator()`.

- [ ] **Step 1: Write the failing test** `tests/test_generator_wiring.py`:
  - `test_default_generator_is_byte_identical_characterization`: build a service over a tiny known corpus (reuse `build_benchmark_service(tmp)` from benchmark), call `research_cve(<an indexed id>, role="research_analyst")`, assert `res.answer` equals a captured golden string AND `read_records(audit)[-1]` has `model_id == "retrieval-only"`, `conclusion == "retrieval-only: assembled from cited passages"`, and the same `model_output`. *(Characterization/RF4 — passes on current code; must stay green after the change.)*
  - `test_injected_generator_fills_model_output`: a `_RecordingGen` whose `generate` returns `"synthetic claim [CVE-...]"` for a retrieved id; inject it; assert that cited line appears in `res.answer` (it is grounded) and the audit `model_output` is the generator's text.
  - `test_injected_generator_identity_lands_in_audit`: a fake with `model_id="ollama"`, `model_version="mistral:latest"`, `prompt_template_version="v1"`; assert the audit record carries those three and `conclusion == "ollama: assembled from cited passages"`.
- [ ] **Step 2: Run the three tests; verify the two new ones FAIL** (`research_cve(..., generator=...)`/injection not wired ⇒ `TypeError`/assertion), the characterization PASSES on current code.
- [ ] **Step 3: Implement** `JoinGenerator` in `generation/join.py`; add the `generator` kw-only param to `__init__`; in `_research`, replace line 205 with `passages = [f"{h.text} [{h.document_id}]" for h in hits]; model_output = self._generator.generate(objective, passages)`, read identity via `mid = getattr(self._generator, "model_id", "retrieval-only")` (and `model_version`/`prompt_template_version` likewise), set those record fields and `conclusion=f"{mid}: assembled from cited passages"`. Leave the `build_report(record)` call unchanged (Task 3 adds passages).
- [ ] **Step 4: Run tests; verify all three PASS.**
- [ ] **Step 5: Run the full default suite** `./.venv/bin/pytest -q -m "not integration"`; **Expected: all green** (byte-identity holds).
- [ ] **Step 6: Commit** `feat(gen): wire Generator seam into id-route with deterministic JoinGenerator default`

---

### Task 2: `OllamaGenerator` (stdlib HTTP, hermetic unit tests)

**Files:**
- Create: `src/secure_ai_research/generation/ollama.py`
- Test: `tests/test_ollama_generator.py`

**Interfaces:**
- Consumes: the identity-attr convention from Task 1.
- Produces:
  - `class GeneratorError(RuntimeError)`.
  - `OllamaGenerator(model: str, host: str = "http://localhost:11434", *, timeout: float = 60.0, _post: Callable[[bytes], bytes] | None = None)`; attrs `model_id="ollama"`, `model_version=model`, `prompt_template_version="v1"`; method `generate(self, prompt: str, passages: Sequence[str]) -> str`.
  - `_post` is the injection seam for hermetic tests (default: a module function doing the real `urllib.request` POST to `{host}/api/generate` with the timeout). `generate` builds the JSON body `{"model": model, "prompt": <template>, "stream": False, "options": {"temperature": 0}}`, decodes the `{"response": str}` field, and raises `GeneratorError` on any non-2xx, timeout, decode failure, or missing/empty `response`.

- [ ] **Step 1: Write the failing tests** (all hermetic — inject `_post`):
  - `test_satisfies_generator_protocol`: `isinstance(OllamaGenerator("mistral:latest", _post=...), Generator)`.
  - `test_generate_returns_response_text`: `_post` returns `b'{"response": "a grounded line [CVE-2021-44228]"}'`; assert `generate(...)` returns that string.
  - `test_request_sets_temperature_zero_and_model`: capture the body passed to `_post`; assert it decodes to a dict with `model`, `options.temperature == 0`, `stream == False`, and the passages appear in `prompt`.
  - `test_empty_response_raises` (RF1): `_post` returns `b'{"response": "   "}'` ⇒ `pytest.raises(GeneratorError)`.
  - `test_transport_failure_raises`: `_post` raises `URLError`/`TimeoutError` ⇒ `GeneratorError`.
  - `test_identity_attrs`: `model_id=="ollama"`, `model_version=="mistral:latest"`.
- [ ] **Step 2: Run tests; verify they FAIL** (module/class absent).
- [ ] **Step 3: Implement** `generation/ollama.py` as specified. Prompt template: a short instruction block — "Using only the numbered passages, write one claim per line; end each line with the `[DOC-ID]` exactly as shown in the passage it is grounded in; cite only these passages; no preamble." followed by the id-tagged passages and the objective, with passages and objective in clearly delimited sections (hygiene; no injection-immunity claimed — §10 Q5).
- [ ] **Step 4: Run tests; verify PASS.**
- [ ] **Step 5: Commit** `feat(gen): add OllamaGenerator (stdlib urllib, temp 0, fail-closed)`

---

### Task 3: Faithfulness floor in `build_report` + service passes passages

**Files:**
- Modify: `src/secure_ai_research/reporting/report.py` (`build_report`)
- Modify: `src/secure_ai_research/research_service.py` (`_research`: pass passages to `build_report`)
- Test: `tests/test_report_faithfulness.py`

**Interfaces:**
- Consumes: `citation_ids` (same module), the service wiring from Task 1.
- Produces: `build_report(record: ResearchRecord, passages: Mapping[str, Sequence[str]] | None = None, *, min_overlap: float = 0.3) -> str`. When `passages` is `None`, behaviour is exactly today's. When provided, a line surviving the id-check is **additionally** kept only if, for at least one id it cites, its claim tokens overlap that id's passage text by ≥ `min_overlap` (overlap = |claim_tokens ∩ passage_tokens| / |claim_tokens|, tokens = lowercased alphanumeric words with citation tokens stripped; a line with no claim tokens is kept).

- [ ] **Step 1: Write the failing tests**:
  - `test_passages_none_is_unchanged` (guard): for a crafted record, `build_report(record) == build_report(record, None)` and equals today's expected string.
  - `test_invented_claim_with_valid_id_is_dropped` (RF3/A1): record `model_output = "Remote code execution confirmed [CVE-2021-44228]"`, `retrieved_doc_ids=["CVE-2021-44228"]`, `passages={"CVE-2021-44228": ["Log4j JNDI lookup logging library issue"]}` (no shared content words) ⇒ the line is **absent** from the report body (`No cited findings.`).
  - `test_passage_text_line_is_kept` (byte-identity shape): a line that *is* the passage plus its `[id]` ⇒ kept (overlap 1.0).
  - `test_faithful_paraphrase_is_kept`: a line sharing ≥ half its words with the passage ⇒ kept at default `min_overlap`.
- [ ] **Step 2: Run tests; verify the invented-claim test FAILS** on current `build_report` (it keeps the line), guard/kept tests pass.
- [ ] **Step 3: Implement** the faithfulness filter in `build_report` (helper `_claim_tokens(line)` and `_is_faithful(line, cited_passages, min_overlap)`); in `_research`, build `passages_by_id = {did: [h.text for h in hits if h.document_id == did] for did in ordered_ids}` and call `build_report(record, passages_by_id)`.
- [ ] **Step 4: Run tests; verify PASS.**
- [ ] **Step 5: Run the full default suite**; **Expected: green**, incl. the Task-1 characterization (deterministic lines contain a full passage ⇒ overlap 1.0 ⇒ byte-identity preserved).
- [ ] **Step 6: Commit** `feat(report): drop unfaithful claim lines via a lenient token-overlap floor`

---

### Task 4: Config + `make_generator` factory + API wiring

**Files:**
- Modify: `src/secure_ai_research/config.py` (`Settings`)
- Create: `src/secure_ai_research/generation/factory.py`
- Modify: `src/secure_ai_research/api/deps.py` (`get_service`)
- Test: `tests/test_generation_factory.py`, `tests/test_api_generator_wiring.py`

**Interfaces:**
- Consumes: `JoinGenerator` (T1), `OllamaGenerator` (T2), `Settings`.
- Produces: `make_generator(settings: Settings) -> Generator` — `OllamaGenerator(settings.generation_model, settings.ollama_host)` when `settings.generator == "ollama"`, else `JoinGenerator()`. `Settings` gains `generator: Literal["join", "ollama"] = "join"` and `generation_model: str = "mistral:latest"` (reuses existing `ollama_host`).

- [ ] **Step 1: Write the failing tests**:
  - `test_factory_defaults_to_join`: `make_generator(Settings())` is a `JoinGenerator`.
  - `test_factory_builds_ollama_when_selected`: `make_generator(Settings(generator="ollama", generation_model="mistral:latest"))` is an `OllamaGenerator` with `model_version == "mistral:latest"`.
  - `test_api_default_answer_unchanged` (hermetic): with default settings, an endpoint (`GET /research/cve/{id}` via `TestClient`, existing dependency-override pattern) returns the deterministic answer — no Ollama.
  - `test_api_uses_injected_generator` (hermetic): override `get_service` with a service built with a `_RecordingGen`; assert the endpoint's answer reflects the fake's grounded line (proves G2 end-to-end without real Ollama).
- [ ] **Step 2: Run tests; verify they FAIL** (factory/settings fields absent).
- [ ] **Step 3: Implement** the `Settings` fields, `make_generator`, and wire `get_service` to `generator=make_generator(settings)` in the `ResearchService(...)` call.
- [ ] **Step 4: Run tests; verify PASS**, then full default suite green.
- [ ] **Step 5: Commit** `feat(gen): config-selectable generator, default join, wired at API startup`

---

### Task 5: Benchmark generator param + real integration eval (measured, `-m integration`)

**Files:**
- Modify: `src/secure_ai_research/evaluation/benchmark.py` (`build_benchmark_service`)
- Modify: `src/secure_ai_research/evaluation/model_eval.py` (add a measurement entry; keep `injection_following_rate`)
- Test: `tests/test_model_eval_seam.py` (un-skip the Week-16 real test → `integration`); Create `tests/test_integration_ollama_eval.py`

**Interfaces:**
- Consumes: `OllamaGenerator` (T2), `build_benchmark_service`, `run_benchmark`, `aggregate`, `injection_following_rate`, `run_injection_eval`.
- Produces: `build_benchmark_service(audit_path: Path, generator: Generator | None = None) -> ResearchService` (passes `generator=` through to `ResearchService`; `None` ⇒ today's default, benchmark stays deterministic). `evaluation/model_eval.measure_real_eval(generator: Generator, audit_path: Path) -> dict[str, float]` returning `{"grounding", "citation_accuracy", "injection_following_rate", "n_answered"}` by running the benchmark through a service built with `generator`.

- [ ] **Step 1: Write the failing tests**:
  - `test_build_benchmark_service_default_is_deterministic` (hermetic, guard): two default `build_benchmark_service` runs ⇒ identical `aggregate(run_benchmark(...))` (confirms the new param's default didn't disturb the 1.0 path).
  - In `tests/test_integration_ollama_eval.py`, `@pytest.mark.integration` tests that **skip when Ollama is unreachable** (RF5 — a module-level `pytest.importorskip`-style reachability probe to `settings.ollama_host`, else `pytest.skip("Ollama not reachable")`):
    - `test_real_eval_is_non_vacuous_and_grounded`: build `OllamaGenerator("mistral:latest")`, `m = measure_real_eval(gen, tmp)`; assert `m["n_answered"] > 0` and `m["grounding"] >= _GROUNDING_FLOOR`; print `m`.
    - `test_real_generator_injection_following_within_ceiling` (un-skipped Week-16 RF5): assert `injection_following_rate(OllamaGenerator("mistral:latest")) <= _INJECTION_CEILING`; print the rate.
  - Replace `tests/test_model_eval_seam.py::test_real_generator_never_follows_injection` (currently `@pytest.mark.skip`) with a pointer comment to the new integration test (the fakes `_Parrot`/`_Refuser` discrimination tests stay as the hermetic seam proof).
- [ ] **Step 2: Run the hermetic guard test; verify behaviour.** Run `./.venv/bin/pytest -q -m integration tests/test_integration_ollama_eval.py` with Ollama **down** once to confirm it SKIPS (RF5), not fails.
- [ ] **Step 3: Implement** the `generator` param on `build_benchmark_service`; `measure_real_eval`; the integration tests with the reachability skip; set `_GROUNDING_FLOOR` / `_INJECTION_CEILING` as placeholders.
- [ ] **Step 4: Mandatory real run.** Start from the known-running Ollama (`mistral:latest`). Run `./.venv/bin/pytest -q -m integration tests/test_integration_ollama_eval.py`; read the printed `grounding`, `citation_accuracy`, `injection_following_rate`. **Set `_GROUNDING_FLOOR` conservatively below the observed grounding and `_INJECTION_CEILING` conservatively above the observed follow-rate**, re-run green, and record the observed numbers + chosen thresholds in the ledger (closes G4/G5; honest numbers, not 1.0).
- [ ] **Step 5: Run the full default suite** `-m "not integration"`; **Expected: green** (integration tests excluded; deterministic gate untouched).
- [ ] **Step 6: Commit** `feat(eval): real Ollama model-behaviour eval behind -m integration (measured grounding + injection-following)`

---

## Self-Review

**1. Spec coverage:** G1→T2; G2→T1+T4; G3→T1(characterization)+T3(faithfulness byte-identity)+T5(benchmark guard); G4→T5; G5→T5 step 4; G6/§11 faithfulness→T3; §10 Q1 fail-closed→T1 Global-Constraint + (FETCH_ERROR mapping implemented in T1 step 3; **note:** add an explicit T1 sub-assertion that an injected generator raising `GeneratorError` yields `Outcome.FETCH_ERROR` with one audit record); Q2 audit identity→T1; Q4 empty-hits→unchanged terminal path (no task needed, asserted implicitly by the deterministic suite); Q5 untrusted prompt→T2 template; Q6 API wiring→T4; Q7 marker→already registered (confirmed in pyproject), used in T5.
  - **Gap found & fixed:** the generator-failure→`FETCH_ERROR` path (§10 Q1) had no test. **Add to Task 1 Step 1** a `test_generator_failure_is_fetch_error`: an injected generator whose `generate` raises `GeneratorError` ⇒ `res.outcome is Outcome.FETCH_ERROR`, answer `""`, exactly one audit record; and in Step 3 wrap the `_research` generation call so `GeneratorError` emits a terminal `fetch_error: generation failed (<type>)` record (mirrors the existing fetch exception handling at 164–178, type-name only — no payload leak).
**2. Step scan:** each code step names the file + exact signature; bodies are left to the implementer except the overlap formula and the JSON body shape, which the tests pin. No decide-nothing lines.
**3. Type consistency:** `Generator`/`generate(prompt, passages)->str`, `model_id/model_version/prompt_template_version` attrs, `build_report(record, passages=None, *, min_overlap=0.3)`, `build_benchmark_service(audit_path, generator=None)`, `make_generator(settings)->Generator`, `GeneratorError`, `measure_real_eval(generator, audit_path)->dict` — consistent across tasks.
**4. Review Focus:** RF1→T2; RF2→T3; RF3→T3; RF4→T1; RF5→T5 — each owned and tested.
**5. Proportion:** five tasks, signatures + test assertions only, no transcribed bodies; proportional to the design.
