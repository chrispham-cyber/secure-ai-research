# Phase 5 · Slice 1b — Free-form Q&A (`POST /research/ask`) (design)

**Date:** 2026-11-19
**Status:** awaiting approval (brainstorming HARD-GATE — no code until approved)
**Author:** Chris + Claude (Opus 4.8)
**Phase:** 5 · Slice 1b. Builds directly on **Slice 1a** (merged `main`@fcdedd4): the real `Generator` seam, `JoinGenerator` default, `OllamaGenerator`, the `build_report` citation + faithfulness gate, fail-closed `FETCH_ERROR`, config/factory wiring, and the `-m integration` eval pattern. Read the [1a design](2026-11-19-phase5-slice1a-generator-synthesis-design.md) first; 1b inherits all of its constraints and does not re-litigate them.

---

## 1. Intent & why

Slice 1a wired the real LLM into the **id-routes** — "tell me about *this* CVE / *this* ATT&CK technique". Slice 1b delivers the capability the 1a design named as 1b's job (1a §3 non-goals): **free-form Q&A** — a user asks a natural-language question, and the platform retrieves across the **whole** authorized corpus (NVD + ATT&CK + CISA KEV + SigmaHQ) and returns an LLM-written, grounded, cited answer.

Today `POST /research/search` already retrieves across the whole corpus, but it only returns a **ranked list of passages** (its `answer` is a count sentence, computed but deliberately not surfaced — spec §7.1). 1b adds the missing half: **synthesis** — turning those retrieved passages into a single grounded answer to the question.

**Why now:** 1a built and proved every mechanism 1b needs; this slice is the same trust-but-verify pattern applied to the multi-document search path. Ollama/`mistral:latest` is already running locally.

**Success looks like:** `POST /research/ask {"query": "which Log4j vulnerabilities are known-exploited?"}` returns a grounded, cited answer synthesised from the matching corpus documents (or an honest "no cited findings" when nothing matches); the default (unconfigured) generator makes `/ask` deterministic and hermetically testable; `search()` and every Phase-2/3/4 behaviour stay byte-identical; a real integration eval prints measured QA metrics; the hermetic CI gate is unchanged and green.

---

## 2. Goals

- **G1.** A new `POST /research/ask` endpoint + a new `ResearchService.ask(query, *, role, limit=5) -> ResearchResult` method (a sibling of `search()`): free-text question → LLM-synthesised, grounded, cited answer over the **whole authorized corpus**.
- **G2.** **Reuse 1a unchanged.** `ask()` routes `model_output` through the already-injected `Generator` (default `JoinGenerator`, opt-in `OllamaGenerator` via the *same* `SAIR_GENERATOR` config), and gates the output through the existing `build_report` citation + faithfulness filter. No change to the `Generator` Protocol, `OllamaGenerator`, `factory`, or config; the sole `build_report` change is the additive citation-grammar widening (G6). One audit record per call, carrying the active generator's identity (1a's `getattr` convention).
- **G3.** **Everything else stays byte-identical.** `search()`, the two id-routes, and all Phase-2/3/4 behaviour are unchanged. If a shared retrieval helper is extracted (§7), `search()`'s answer **and** audit record are proven byte-identical by a characterization test — the same discipline 1a applied to the default path.
- **G4.** **Empty / no-match question is an honest OK, with no generation.** When the relevance floor leaves zero hits, `ask()` returns `Outcome.OK` with a deterministic "no cited findings" answer **without invoking the generator** (no wasted model call; no invention from an empty context). One audit record, naming zero retrieved docs.
- **G5.** A real **model-behaviour eval** for the QA path behind `-m integration`: free-text questions answered through an `OllamaGenerator`, measured (grounding / citation / grounded-answers) and **non-vacuous**; hermetic tests pin grounding-enforcement, authz, fail-closed, empty, and adversarial-generator behaviour.
- **G6.** **Additively widen the citation grammar** (Chris's call, §11) so KEV (`KEV-CVE-…`) and Sigma (`SIGMA-<uuid>`) documents are citable by `build_report`/`citation_ids` — without which `/ask` over the whole corpus silently drops every KEV/Sigma-grounded line. Purely additive: existing id-route / search / default output and all Phase-4 metric inputs are unchanged, and the deterministic 1.0 gate is re-run to confirm. This is the **only** change to `build_report` in 1b.

## 3. Non-goals (explicitly out of this slice)

- **Changing `POST /research/search`.** Search stays the ranked-list endpoint, contract byte-stable. `/ask` is the synthesis sibling, not a replacement; search's `answer` stays unsurfaced.
- **A QA agent tool.** `AgentToolset` keeps its three read tools; a `ask`/`qa` agent tool is a later increment, not 1b.
- **Structured / JSON-constrained generation** — deferred (1a Approach B), adopted only if measured grounding is too low.
- **Multi-turn chat, conversation memory, query rewriting/expansion, re-ranking** — 1b answers one question over the existing deterministic retrieval; it does not improve retrieval.
- **Making the LLM the default** — opt-in via the same `SAIR_GENERATOR` as 1a; the default is `JoinGenerator`.
- pgvector, MinIO, OIDC, encryption, SBOM — later slices.

## 4. Anti-goals (a failure even if it "works")

- **A1 — ungrounded output reaches the user.** If the LLM invents a claim, cites a non-retrieved id, or embellishes beyond the passage, and it survives into the `/ask` answer, the core promise is broken. `build_report`'s citation rule + the 1a faithfulness floor must drop every such line regardless of what the generator emits — proven by a dedicated **adversarial-generator-through-`ask()`** hermetic test.
- **A2 — `/ask` leaks a document the caller may not see.** Free-text QA retrieves over the whole corpus, so the authorize-before-retrieve invariant is load-bearing here exactly as in `search()`. A RESTRICTED doc (senior-only) must never surface in a `research_analyst`'s `/ask` answer or citations. Proven by a **two-user info-disclosure test on `/ask`** (mirrors the Week-10/15 tests), including the body-only canary.
- **A3 — non-determinism leaks into the hermetic suite.** Hermetic `/ask` tests use `JoinGenerator` / fakes only; the real model is `integration`-only, asserted on properties, never byte-equality.
- **A4 — a vacuous QA eval** reporting a number while measuring nothing (Week-15 lesson): the integration eval must prove non-vacuity (real questions answered, real passages retrieved, ≥1 grounded answer).
- **A5 — `search()` or any shipped behaviour silently changes.** Any refactor touching `search()` is gated by a byte-identity characterization test; the blast radius is stated and minimal.

## 5. Constraints

Inherits **all** of 1a §5 (posture split: default `pytest -m "not integration"` stays hermetic/deterministic/offline, real Ollama only under `-m integration`; `Generator` Protocol unchanged; **no new runtime dependency**; fail-closed; local git, **no remote, no push without Chris's go**; opt-in by config, default `JoinGenerator`). Specific to 1b:

- **No new config.** `/ask` uses the **same** injected `Generator` the service already holds (the generator is a corpus-wide capability, not per-endpoint). `deps.get_service` already builds the service with `make_generator(settings)`; `/ask` inherits it. No new env var.
- **One authorize-before-retrieve path.** `/ask`'s scope is the whole set the role may see (like `search()`), never intersected with an id. Authorization runs **before** the store is queried. If a shared helper is extracted, it is the single place authz happens for both search and ask (a security plus: one path to get right).

---

## 6. Approaches considered

**(A) New `POST /research/ask` endpoint + `ask()` method, reusing the 1a Generator + `build_report` gate — CHOSEN.**
The 1a design already fixed this surface (1a §3: *"Free-form Q&A (`POST /research/ask`) — that is Slice 1b, built on this slice's Generator"*). `ask()` is a sibling of `search()` that retrieves the same way and then **synthesises** instead of listing. Smallest change that delivers QA; every enforcement mechanism (citation filter, faithfulness floor, fail-closed, audit identity) is already built and proven in 1a; search's shipped contract is untouched.
*Trade-off:* a fluent model that wanders from one-claim-per-line loses lines (lower measured grounding) — acceptable, and what the eval reveals. Free-text questions are *more* exposed to prompt-injection than the id-routes (the user's question is attacker-controllable and the corpus is broad); 1b **measures** injection-following and does **not** claim immunity (honest Week-11 scope), with `build_report` as the control on output.

**(B) Add a synthesised `answer` to `POST /research/search` (e.g. a `synthesize: bool` flag).**
**Rejected.** Conflates two user intents (ranking "which documents" vs answering "what's the answer") in one endpoint; mutates a shipped contract (even additively) against 1a's "don't touch the byte-stable sibling" discipline; makes the search 200 body conditional on a flag. A clean separate endpoint is simpler and safer.

**(C) Structured / grammar-constrained QA.** Deferred, identical rationale to 1a Approach B — adopt only if (A)'s measured grounding is too low.

---

## 7. The decided how

- **`ResearchService.ask(query, *, role, limit=5) -> ResearchResult`** (new sibling of `search()`):
  1. `rid`/`analyst_id`/`now`; `objective = f'Answer question: "{query}"'`.
  2. **Authorize-before-retrieve:** `allowed = {id for id,doc in snapshot if authorize(role,doc)}`; empty → one terminal `DENIED` record, return `DENIED`.
  3. **Relevance-floored retrieval** (identical rule to `search()`): store query over `allowed`, keep `hit.score > 0`; dedup to `ordered_ids` + best `first_text` per doc; build `citations`.
  4. **Empty-hits guard (G4):** if `not ordered_ids` → **do not call the generator**; emit one record (`retrieved_doc_ids=[]`, `model_output=""`, `model_id="retrieval-only"`), return `OK` with the deterministic empty answer (`build_report` over an empty record ⇒ "No cited findings.").
  5. **Synthesis:** `passages = [f"{h.text} [{h.document_id}]" for h in hits]`; `model_output = self._generator.generate(query, passages)` inside the **same fail-closed try/except as 1a** (`GeneratorError` or any `Exception` → one terminal `FETCH_ERROR` record, return `FETCH_ERROR`; no fallback, no payload leak).
  6. Build the `ResearchRecord` with the active generator's identity (`getattr` convention), `retrieved_doc_ids=ordered_ids`; `passages_by_id = {id: [h.text for h in hits if h.document_id==id] for id in ordered_ids}`; `answer = build_report(record, passages_by_id)` (citation + faithfulness gate); emit; return `OK` with `answer` + `citations`.
- **Shared retrieval helper (my call, recommended).** Extract the authorize + floored-query + dedup block (steps 2–3, shared verbatim with `search()`) into a private helper used by both `search()` and `ask()`, so authorize-before-retrieve lives in **one** place. `search()` is refactored to call it and **pinned byte-identical** (answer + audit + results) by a characterization test. *Builder's fallback:* if the extraction proves awkward, `ask()` may duplicate the ~15 deterministic lines and leave `search()` untouched (zero blast radius) — the DRY cleanup then becomes a deferred minor. Either way `search()` stays byte-stable.
- **Route `POST /research/ask`** (in `api/routers/research.py`): `AskRequest(query: strip, 1–512 chars; limit: int 1–20)` → **422 by pydantic validation before the handler** (no audit on a malformed request, like `/search`). `res = service.ask(req.query, role=x_role, limit=req.limit)`; `OK → 200 {answer, citations:[asdict...], research_id}`; `DENIED → 403`; `FETCH_ERROR → 503 {"detail":"upstream source unavailable", research_id}`. **No 404** (a non-matching question is a valid 200 with an empty answer, mirroring search). Same `X-Role` dev-stub security banner as the other routes.
- **Config / factory / deps:** **unchanged.** `/ask` inherits the service's injected generator; `make_generator(settings)` already runs at startup. Turning on the LLM for `/ask` is the same `SAIR_GENERATOR=ollama` that 1a added.
- **Citation grammar (G6, additive).** `reporting/report.py`: widen `_CITATION` to also match `KEV-CVE-\d{4}-\d{4,}` and `SIGMA-<uuid>` (KEV-CVE ordered before bare CVE); `citation_ids` and `build_report` inherit it. Re-run `tests/test_eval_regression_gate.py` + the full `-m "not integration"` suite to confirm byte-identity of every existing surface (id-routes, search, Phase-4 metrics). This is the only `build_report` edit in 1b.
- **Eval (`-m integration`):** extend the integration eval with a small set of free-text questions answered through `ask()` on an `OllamaGenerator`-backed benchmark service; report grounding / citation_accuracy / grounded-answers for the QA path, with a non-vacuity floor (≥1 grounded answer, real retrieval). Reuse `build_benchmark_service(generator=...)` from 1a; no corpus fork. Conservative thresholds set from the first real run, recorded in the ledger. (The existing deterministic gate and `THRESHOLDS` are untouched.)
- **Tests (hermetic, TDD spine):**
  - `ask()` with `JoinGenerator` over the benchmark corpus → grounded, cited `OK` answer spanning the matching docs; deterministic.
  - **A1 adversarial:** an adversarial fake generator (uncited + forged-id of **any** shape incl. a non-retrieved `[KEV-CVE-9999-9999]` + valid-id-invented lines) through `ask()` → none survive in `res.answer`; "No cited findings." when all dropped.
  - **G6 grammar:** `citation_ids` recognises `[KEV-CVE-…]` and `[SIGMA-…]`; a KEV/Sigma-grounded `/ask` line (default `JoinGenerator`) survives into a non-empty answer; existing `[CVE-…]`/`[T####]` parsing is unchanged (characterization). The deterministic eval gate + full hermetic suite stay green/byte-stable after the widening.
  - **A2 info-disclosure:** `research_analyst` `/ask` never surfaces the RESTRICTED doc id or its body-only canary; `senior_analyst` can; across the route (TestClient) too.
  - **G4 empty:** a query matching nothing → `OK`, empty answer, **generator not called** (assert via a recording fake), one audit record with `retrieved_doc_ids=[]`.
  - **Fail-closed:** a `GeneratorError`-raising and a non-`GeneratorError`-raising generator → `FETCH_ERROR` + exactly one audit record (route → 503).
  - **DENIED:** a role that may see nothing → `DENIED` (403), store never queried.
  - **G3 characterization:** `search()` answer + audit byte-identical before/after the helper extraction.
  - **Route:** `AskRequest` validation (422 on empty/too-long/bad limit, no audit); 200/403/503 mapping (fake generator, no real Ollama).
- **Tests (integration, `-m integration`, needs Ollama):** real `mistral` answers representative questions through `/ask`; surviving cited ids ⊆ retrieved; grounding ≥ floor; measured eval non-vacuous. **Property assertions only.**

## 8. Left to the builder

- Exact `objective`/prompt wording passed to `generate()` for the QA path (the question is the prompt; iterate against measured grounding — 1a's one-claim-per-line + cite-only-given-passages template is the starting point).
- Shared-helper extraction vs. controlled duplication (§7) — recommended: extract, with the `search()` characterization test.
- Exact empty-answer text (reuse `build_report`'s "No cited findings." — preferred, single-sourced — vs. a search-style "No documents matched").
- Which free-text questions seed the integration eval, and whether it runs a QA subset or the full set (speed); the conservative QA thresholds (measure first).
- `AskRequest` field names/limits may reuse `SearchRequest`'s exactly (query 1–512, limit 1–20) — recommended for consistency.

## 9. Testing & review posture (unchanged gates)

TDD iron law (every change RED→GREEN). Default `pytest -m "not integration"` stays the hermetic CI gate — green and byte-stable (incl. the 1.0 Phase-4 eval gate and the `search()` characterization). One fresh **opus-xhigh** whole-branch review at the end (Chris's standing per-slice gate). Merge to **main, local only**, at finish. **No push without Chris's explicit go-ahead.** Mandatory real integration run with Ollama up, numbers recorded in the ledger (anti-goal A4).

---

## 10. Builder-check resolutions (calls I made — check these while reviewing)

A fresh engineer read this doc against the code. One finding is the owner's call (Q1, §11); the rest I settled:

- **Q1 — KEV/Sigma ids are not citable by `build_report` today** (`_CITATION`/`citation_ids` match only `[CVE-…]`/`[T####]`, but KEV ids are `KEV-CVE-…` and Sigma ids `SIGMA-<uuid>`). So a `/ask` line grounded only in a KEV or Sigma doc is dropped as uncited — conflicting with the "whole corpus" goal. **This changes what gets built → Chris's call, resolved in §11.** (The A2 RESTRICTED doc is CVE-shaped `CVE-2099-7001`, so the info-disclosure test is unaffected either way.)
- **Q2 — `citations` vs `answer` may diverge; `/ask` mirrors `_research`.** `citations = [Citation(did,…) for did in ordered_ids]` is the *retrieved* set (built before generation); `answer = build_report(...)` is the *faithfulness-filtered* report. A "No cited findings." answer alongside a non-empty `citations` list is the same property the id-routes already have (citations = "considered", answer = "faithfully grounded"). The eval's `citation_accuracy` reads `citation_ids(answer)` (survivors), independent of the `citations` list, so this choice doesn't move measured numbers. My call.
- **Q3 — `/ask` reuses `build_report` unchanged** → the answer is the full report wrapper (`# Research report: Answer question: "<query>"\n\n<grounded lines>\n\nSources: <ids>`), identical in shape to the id-routes; the empty path (G4) is `build_report` over an empty-retrieved record = the same wrapper with a `No cited findings.` body. Single-sourced, no bespoke empty string. My call.
- **Q4 — the prompt passed to `generate()` is the raw `query`** (the user's question), not the audit `objective`. `OllamaGenerator` renders it as `Question: {prompt}`, so the raw question is right; the audit `objective` stays `Answer question: "<query>"`. §7 step 5 (`generate(query, passages)`) is authoritative. My call.
- **Q5 — `limit` is a chunk budget** (as in `search()`), passed straight to the store query; several chunks may come from one document, so `limit` bounds passages scanned, not documents answered (the same spec-§8 simplification `search` documents). `ask()` does not use `self._limit` (that is the id-route's). My call.
- **Q6 — the empty-hits record (G4) is a normal OK record, not `_emit_terminal`.** `_emit_terminal` returns a non-OK outcome; G4 is an **OK** with an empty answer. Emit a `ResearchRecord` with `retrieved_doc_ids=[]`, `model_output=""`, `model_id="retrieval-only"` (generator not called), `conclusion=f"retrieval-only: no documents matched"`; `answer = build_report(...)` over it → `No cited findings.`; return `OK`. Builder picks the exact conclusion wording; one record either way. My call.
- **Q7 — the successful `/ask` record follows `_research`:** `conclusion=f"{model_id}: assembled from cited passages"`, `model_output` = the raw generator output (including lines `build_report` later drops — intended; the audit captures what the model produced, the answer is what survived). My call.
- **Q8 — QA metrics reuse the existing evaluator functions** (`metrics.grounding`, `metrics.citation_accuracy`) over `EvalResult`s whose answers come from `ask()`; no new metric code. The integration harness adds a free-text question set + an `ask()`-dispatching variant of the Week-16 `measure_real_eval` (small, local). Builder seeds the questions. My call.
- **Q9 — the `search()` characterization baseline is captured BEFORE the helper extraction** (record `search()`'s answer + audit over a representative corpus; assert byte-identical after). Standard refactor discipline; if the baseline cannot be cleanly captured, fall back to the duplicate-and-leave-search-untouched option (§7). My call.
- **Q10 — `OllamaGenerator`'s 60s timeout is inherited unchanged;** a slow `/ask` blocks the request thread and a timeout maps to `FETCH_ERROR`→503 (fail-closed). Acceptable for a local dev service; tuning deferred. My call.

## 11. The one open call — for Chris

**Can `/ask` cite KEV and Sigma documents?** `build_report`'s citation grammar recognises only `[CVE-…]` and `[T####]`. KEV (`KEV-CVE-…`) and Sigma (`SIGMA-<uuid>`) documents — half the corpus, and the *known-exploited* + *detection* half that is much of the platform's value — cannot be cited, so any `/ask` line grounded only in them is dropped, even under the default `JoinGenerator`. Three ways:

- **(a) Widen the citation grammar (recommended).** Extend `_CITATION`/`citation_ids` to also match `KEV-CVE-…` and `SIGMA-<uuid>`, so `/ask` delivers true whole-corpus QA. The change is **purely additive**: the id-routes and search produce no KEV/Sigma bracket tokens, so their output — and the Phase-4 metric inputs — are unchanged (re-run the 1.0 gate to confirm). Touches a Phase-4-coupled shared function, so it is called out here rather than made silently.
- **(b) Restrict `/ask` to NVD + ATT&CK.** No `build_report` change, but `/ask` cannot answer from KEV or Sigma — the "known-exploited" and "detection" questions fail. Keeps 1b minimal at the cost of the feature's reach.
- **(c) Accept the degradation** and document that KEV/Sigma-only lines are dropped. Rejected in spirit — it makes the "whole corpus" claim dishonest.

**Decision (Chris, 2026-11-19): (a) — widen the citation grammar.** Concrete resolution:
- `reporting/report.py` `_CITATION` (and the shared `citation_ids` it backs) gains two alternatives: `KEV-CVE-\d{4}-\d{4,}` and `SIGMA-<uuid-shape>`, matching the namespaced ids the KEV/Sigma loaders mint. Order the `KEV-CVE-…` alternative before bare `CVE-…` (the `[`-anchor already blocks a bare-CVE match inside `[KEV-CVE-…]`, but order it defensively).
- **Additive, proven non-regressive.** The id-routes and `search()` never emit a `[KEV-…]`/`[SIGMA-…]` token (id-route citations are the CVE/T doc itself; `search()` does not call `build_report`), and every Phase-4 eval input is a CVE/T id-route answer or a bracket-free search count — so `citation_ids` returns identical values on all existing inputs and the deterministic 1.0 gate is unchanged. Re-running `tests/test_eval_regression_gate.py` + the full hermetic suite confirms it; the whole-branch review double-checks.
- **New coverage:** a `/ask` line grounded in a KEV or Sigma doc now survives `build_report` and its faithfulness floor. Hermetic tests pin `citation_ids('x [KEV-CVE-2021-44228]') == ['KEV-CVE-2021-44228']` and `… [SIGMA-…]`, a non-empty KEV/Sigma-cited `/ask` answer, and unchanged CVE/T parsing. The A1 adversarial test drops a forged id of **any** shape (incl. a non-retrieved `[KEV-CVE-9999-9999]`).

This is folded into **G6**, §7 (citation-grammar bullet + test), and the A1 test.
