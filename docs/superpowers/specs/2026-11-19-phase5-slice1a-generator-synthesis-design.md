# Phase 5 · Slice 1a — Real Generator + grounded synthesis (design)

**Date:** 2026-11-19
**Status:** awaiting approval (brainstorming HARD-GATE — no code until approved)
**Author:** Chris + Claude (Opus 4.8)
**Phase:** 5 (Hardening & real infra behind the Protocol seams). This is the **first slice that breaks the deterministic/offline/no-LLM posture held through Phases 2–4**, so its constraints below set the pattern every later Phase-5 slice inherits.

---

## 1. Intent & why

Turn the platform from a *deterministic retriever that mechanically lists cited passages* into a real **AI research assistant**: the natural-language "answer" for the existing endpoints (`/research/cve|attack|search`) is written by a **real local LLM** grounded in the retrieved passages, instead of a string-join.

Two payoffs:
1. **A real system.** The headline capability the roadmap promises — an LLM that synthesises evidence — comes online, behind the `Generator` Protocol seam built in Phase 4 Week 16.
2. **An honest eval.** Phase 4 could only measure a *fake* generator (Week-16 `model_eval` discriminated `_Parrot` vs `_Refuser`; the real test was `@pytest.mark.skip`). With a real model we run the Phase-4 benchmark + red-team **through the LLM** and report measured numbers (grounding, citation, injection-following) — closing the Week-16 deferral and its Minor #1 (substring-only follow-detection gets exercised against a real model).

**Why now:** Phase 4 is complete (main@c557b4e); the `Generator` seam + `model_eval` + benchmark/red-team/threshold harness already exist; Ollama **v0.40.16 is running locally with `mistral:latest` (7.2B Q4, 32k ctx), 64 GB RAM** — real numbers are available immediately, no infra to stand up.

**Success looks like:** the existing endpoints return LLM-written, fully-grounded answers when the real Generator is configured; the default (unconfigured) path stays **byte-identical to today**; a one-command integration eval prints real measured metrics for the LLM path; the hermetic CI gate is unchanged and still green.

---

## 2. Goals

- **G1.** A real `OllamaGenerator` implementing the existing `Generator` Protocol (`generate(prompt: str, passages: Sequence[str]) -> str`), talking to local Ollama over HTTP at temperature 0.
- **G2.** `ResearchService` routes `model_output` through an injected `Generator` (default = a deterministic join generator), at the single seam `research_service.py:205`/`:306`. Grounding enforcement (`build_report` line-sanitizer) is unchanged and applied to whatever the Generator emits.
- **G3.** The **default path is byte-identical to today**: the default `Generator` is a `JoinGenerator` whose output equals the current `"\n".join(f"{text} [{id}]")`. The hermetic suite and the 1.0 CI gate do not move.
- **G4.** A real **model-behaviour eval** behind `-m integration`: runs the Phase-4 benchmark + red-team through an `OllamaGenerator` and reports measured grounding / citation / refusal / injection-following. Un-skips Week-16's `test_real_generator_never_follows_injection` (now behind `integration`).
- **G5.** The LLM path has **its own measured thresholds** (conservative floors set empirically from the first real run), kept separate from the deterministic 1.0 gate.
- **G6.** A **deterministic faithfulness floor** (Chris's call X, §11): the sanitizer drops any claim line that lacks minimal token overlap with a cited passage, so a valid-id-but-invented claim cannot reach the user or score grounding = 1.0. Lenient (targets wholesale invention, not paraphrase); byte-identical on the deterministic path; also surfaced as a measured metric.

## 3. Non-goals (explicitly out of this slice)

- **Free-form Q&A** (`POST /research/ask`) — that is **Slice 1b**, built on this slice's Generator.
- **Structured/JSON-constrained generation** — see Approach B; deferred to Phase-5 hardening *only if* the measured grounding is too low.
- pgvector, MinIO, OIDC, encryption, SBOM — later slices.
- Making the LLM the **default** answer path. The deterministic join stays the default; the LLM is opt-in by config.
- Multi-turn chat, conversation memory, or a tool-calling agent (the `AgentToolset` is a separate, already-built subsystem).
- Streaming responses, model management/pulling, or multiple model back-ends (Ollama only).

## 4. Anti-goals (a failure even if it "works")

- **A1 — ungrounded output reaches the user.** If the LLM invents a claim or cites a non-retrieved id and it survives into `answer`, the platform's core promise is broken. `build_report` must drop every uncited / forged-citation line regardless of what the Generator emits. This gets a dedicated hermetic test with an adversarial fake generator.
- **A2 — the LLM silently becomes the default** and the deterministic 1.0 CI gate starts measuring a non-deterministic model (flaky/false green). Default must stay the join; the gate must stay on the deterministic path.
- **A3 — non-determinism leaks into the hermetic suite.** Hermetic tests must never call Ollama nor assert exact LLM strings. The real model is `integration`-only and asserted on *properties*, never byte-equality.
- **A4 — a vacuous LLM eval** that reports 1.0 by measuring nothing (the Week-15 lesson). The integration eval must prove non-vacuity (real items answered, real passages retrieved).
- **A5 — committing model weights, prompts-with-secrets, or any non-public data.** Ollama is local and keyless; nothing to commit. Posture stays PUBLIC/synthetic, local, no remote.

## 5. Constraints

- **Posture shift, contained:** real services live behind the seam and run only under `pytest -m integration`; the default `pytest -m "not integration"` suite stays fully hermetic, deterministic, offline. This split is the Phase-5 pattern.
- **Protocol unchanged:** `Generator.generate(prompt, passages) -> str` stays exactly as Week 16 defined it. Passages are passed **already id-tagged** (`f"{text} [{id}]"`) so the signature need not change and the LLM is shown the `[id]` to reuse. (Consequence: `JoinGenerator.generate` = `"\n".join(passages)` reproduces today's output exactly.)
- **No new runtime dependency:** the Ollama HTTP call uses stdlib `urllib.request` with a timeout (no httpx/requests added to runtime deps). Keyless localhost call.
- **Determinism knobs:** `temperature: 0`, `stream: false`. Even so, Ollama output is not guaranteed bit-stable — hence property-based integration assertions only.
- Local git, **no remote**, do not push without Chris's go-ahead. Python stdlib + pydantic + fastapi only for runtime. `-I` / `--form-string` handling rules unchanged.
- Model/URL are **configurable** (env), default `mistral:latest` @ `http://localhost:11434`; unset → `JoinGenerator`.

---

## 6. Approaches considered

**(A) Trust-but-verify, reuse `build_report` — CHOSEN.**
The Generator fills `model_output` with one-claim-per-line text carrying `[id]` citations; the existing `build_report` keeps only lines whose every cited id was retrieved and drops the rest; the Phase-4 metrics score the surviving output. The `model_output` field and the line-sanitizer were *built for exactly this* across Phases 1–4. Smallest change that delivers real generation; enforcement is already proven and already tested; the real eval honestly measures violations. The default generator is the deterministic join, so the hermetic world is untouched.
*Trade-off:* a fluent model that wanders from the one-claim-per-line convention loses more lines (lower measured grounding) — acceptable, and exactly what the eval is there to reveal.

**(B) Structured / grammar-constrained generation.**
Force the model to emit `{claims:[{text, cite_ids}]}` and reject claims citing non-retrieved ids. More robust against free-form drift, but more complex, model-capability-dependent (Ollama structured-output support varies), and diverges from the line-based report the whole stack already uses. **Deferred** to Phase-5 hardening, to be adopted *only if* (A)'s measured grounding proves too low.

**(C) Extractive only (LLM reranks/选择 existing sentences, never generates new text).**
Safest — literally cannot hallucinate — but delivers neither the fluent synthesis nor (in 1b) the Q&A Chris asked for. **Rejected:** defeats the slice's purpose.

**(Also rejected) Make the LLM the default answer path.** Breaks posture and the deterministic gate (A2). The deterministic join stays default; the LLM is opt-in.

---

## 7. The decided how

- **Seam & default.** Introduce `Generator` at the existing seam. `ResearchService.__init__(..., generator: Generator | None = None)`; `None` → `JoinGenerator()`. The two `model_output = "\n".join(...)` sites become:
  `passages = [f"{h.text} [{h.document_id}]" for h in hits]; model_output = self._generator.generate(objective, passages)`.
  `JoinGenerator.generate(prompt, passages) = "\n".join(passages)` ⇒ **byte-identical to today**. `build_report(record)` unchanged.
- **`OllamaGenerator`** (`generation/ollama.py`): stdlib `urllib.request` POST to Ollama (`/api/generate` or `/api/chat` — builder's call), `model`/`base_url` from config, `options={"temperature":0}`, `stream=false`, explicit timeout. System/prompt instructs: *synthesise the passages into one grounded claim per line; end each line with the `[DOC-ID]` exactly as shown in the passage it is grounded in; cite only the given passages; no preamble.*
- **Factory** (`generation/factory.py`): `make_generator(settings) -> Generator` — `JoinGenerator` by default, `OllamaGenerator` when the env selects it. API startup wires it; the integration eval constructs `OllamaGenerator` directly.
- **Real eval** (`evaluation/model_eval.py` extended, + an `integration`-marked test): build the benchmark service with an `OllamaGenerator`, run the Week-14 benchmark + Week-15 red-team through it, report measured metrics; un-skip `test_real_generator_never_follows_injection` under `integration`. LLM-path thresholds are separate, measured-then-floored, and documented in the test; they do **not** touch the deterministic `THRESHOLDS`/gate.
- **Tests (hermetic, the TDD spine):**
  - `JoinGenerator` output == today's string for representative hits (byte-identical regression lock for G3).
  - `ResearchService` routes `model_output` through an injected generator (a fake records its input / returns a sentinel).
  - **A1 security test:** an adversarial fake generator that emits uncited lines + a forged `[DOC-NOPE]` citation ⇒ `answer` contains none of them (`build_report` drops all) — the enforcement is proven to hold on *arbitrary* generator output.
- **Tests (integration, `-m integration`, needs Ollama):** `OllamaGenerator` against live `mistral:latest` yields output whose surviving cited ids ⊆ retrieved and whose grounding ≥ the floor; the real-generator injection-following test; the measured eval runs non-vacuously. **Property assertions only — never byte-equality.**

## 8. Left to the builder

- Exact prompt/system wording for `OllamaGenerator` (subject to G1/A1; iterate against the measured grounding).
- `/api/generate` vs `/api/chat`, and the request timeout value.
- Env var names (e.g. `SAIR_GENERATOR`, `SAIR_OLLAMA_MODEL`, `SAIR_OLLAMA_URL`) — pick and document.
- The empirical LLM-path threshold floors: **measure the first real run, then set conservative floors** (and whether the integration eval runs the full 51-item benchmark or a representative subset for speed).
- (API startup wiring is resolved in §10 — it is **in scope**, config-driven, default unchanged.)

## 9. Testing & review posture (unchanged gates)

TDD iron law (every change RED→GREEN). Default `pytest -m "not integration"` stays the hermetic CI gate and must stay green and byte-stable. One fresh **opus-xhigh** whole-branch review at the end (Chris's standing per-slice gate). Merge to **main, local only** at finish. No push without explicit go-ahead.

---

## 10. Builder-check resolutions (calls I made — check these while reviewing)

A fresh engineer read this doc; here is each gap they flagged and how I settled it. The faithfulness question (§11) is the one call left to Chris.

- **Generator failure (Ollama down / timeout / non-200 / garbage) → raise, never silently fall back.** The service maps a generator failure to a terminal error `Outcome` (sibling of the existing `FETCH_ERROR`/503 upstream-failure path), audited; it does **not** fall back to `JoinGenerator` (that would hide an LLM outage — anti-goal A2) and does **not** fabricate "No cited findings". In the integration eval a generator failure is a hard error, never counted as a pass (anti-goal A4). [Q1]
- **Audit must name the real generator.** `ResearchRecord` hard-codes `model_id="retrieval-only"`, `model_version=""`, `prompt_template_version=""`, `conclusion="retrieval-only: assembled from cited passages"` (research_service.py:214–219). Leaving these would misattribute LLM output as retrieval-only — unacceptable in an audited security platform. Resolution: a generator may expose an optional `info` (model_id, model_version, prompt_template_version, conclusion); the service writes it into the record. **`JoinGenerator.info` = today's exact values**, so the **default audit stays byte-identical** (G3 now explicitly covers the audit log); `OllamaGenerator.info` names the model (e.g. `model_id="ollama"`, `model_version="mistral:latest"`, `prompt_template_version="v1"`). The `generate()` Protocol contract is unchanged, so the Week-16 fakes still satisfy `isinstance`; a generator with no `.info` falls back to the current retrieval-only identity. [Q2]
- **Generator runs only on the non-empty-hits path.** Empty hits already take the terminal path (`model_output=""`, research_service.py ~333) *before* any generation — so DENIED / NOT_FOUND / refusal stays deterministic and the LLM is never invoked with zero passages (invention risk avoided); empty-path byte-identity is automatic. [Q4 — answered by existing structure]
- **`build_benchmark_service(audit_path)` gains an optional `generator=None`** (default preserves today's behaviour); the integration eval passes an `OllamaGenerator`. No separate factory for the eval. [Q3a]
- **The user query / objective is untrusted text in the prompt.** Output grounding (`build_report`) protects the OUTPUT regardless; prompt-level injection via the query is **measured** by the injection-following eval, **not claimed** to be neutralised — the honest Week-11 scope. The prompt template delimits passages vs. the query/objective as basic hygiene, with no immunity claimed. [Q5]
- **API startup wires the factory (config-driven), default = `JoinGenerator`** — so "endpoints return LLM answers when configured" (G2) is true end-to-end. One hermetic API-level test injects a fake generator (no real Ollama). Tightens §8: API wiring is in scope. [Q6]
- **`integration` marker registered in pyproject; integration tests skip with a clear reason when Ollama is unreachable** (CI without Ollama stays green) — AND executing this slice includes a mandatory real run with Ollama up, numbers recorded in the ledger, so a green-but-unrun eval can't hide (anti-goal A4). [Q7]

## 11. The one open call — for Chris

`build_report` and the grounding metric check that **every cited id was retrieved**. They do **not** check that the claim's *text* is actually supported by the passage it cites. A real model (mistral) can therefore write an embellished or invented claim, tag it with a *valid* retrieved id, and still score grounding = 1.0 — a hole that would make the "honest eval" read dishonestly high (partially anti-goal A4).

Two ways for THIS slice:

- **(X) Add a cheap deterministic faithfulness floor (recommended).** Each surviving claim line must share enough lexical overlap with its cited passage (token-overlap ≥ a threshold) or it is dropped / penalised. In-posture (no LLM-judge); closes the crudest "valid-id + invented-text" gaming. *Caveat:* lexical overlap is a crude guard, not true semantic faithfulness — a real faithfulness metric needs an LLM-judge, which stays deferred. Adds one metric + tests to 1a.
- **(Y) Defer faithfulness entirely.** 1a measures id-level grounding + injection-following only; disclose the gap honestly (Week-11 style) and build a dedicated faithfulness eval later. Keeps 1a minimal.

**Recommendation: (X)** — mistral *will* embellish, and id-only grounding would report a number we can't stand behind. (Y) is defensible if you want 1a minimal with faithfulness as its own slice.

**Decision (Chris, 2026-11-19): (X).** Concrete resolution, folded into G6 / §7:
- **Enforced *and* measured.** A surviving claim line must share at least a minimal **token overlap** with the text of at least one passage it cites, or the sanitizer **drops it** (extends `build_report`'s existing drop rule). The same per-line faithfulness is reported as a measured eval metric.
- **Deterministic path stays byte-identical.** `JoinGenerator`'s claim text *is* the passage text (`"{hit.text} [{id}]"`) ⇒ overlap is total ⇒ every line passes ⇒ G3 byte-identity holds. Only the LLM path, where claim text diverges, is exposed to the floor.
- **Lenient threshold, on purpose.** The floor targets *wholesale invention* (a claim with essentially no words from any cited passage), **not** paraphrase — a strict floor would punish the fluent paraphrase that is the LLM's whole purpose. Honest scope: this is a crude lexical guard against the crudest gaming; true semantic faithfulness needs an LLM-judge, which stays deferred. The exact threshold is set empirically (§8).
- **Input change:** the sanitizer needs each cited passage's *text* (not just the retrieved id set) to compute overlap — a small widening of `build_report`'s inputs. Builder's call on the exact shape.
