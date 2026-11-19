# Phase 4 — Evaluation & Red-Teaming — Design

**Status:** proposed (awaiting approval)
**Date:** 2026-11-19
**Repo:** `/Users/fox/Chris/CyberBase/secure-ai-research` (local, no remote, `main@d2c5d5a`)
**Follows:** Phase 3 complete (Weeks 9–12). ROADMAP Phase 4 = weeks 13–16.

---

## 1. Intent & why

Phase 4's ROADMAP objective: *"measure grounding, citation accuracy, refusal, and
robustness — not vibes."* We have, after Phases 2–3, a deterministic, offline,
authorize-before-retrieve, cited-report pipeline over a PUBLIC corpus (NVD + MITRE
ATT&CK + CISA KEV + SigmaHQ). What we do **not** have is a *number* that says how well
it grounds its answers, how accurate its citations are, whether it refuses when it
should, and whether the Week-10/11 security properties hold under adversarial input.

This phase produces a **reproducible, deterministic, offline benchmark + metrics + red-team
evals + a results report + a CI regression gate** over that existing pipeline — so a claim
like "every answer line is grounded in a cited retrieved passage" stops being an assertion
and becomes a measured, re-runnable, regression-gated fact.

Audience: Chris's "Secure AI Systems Engineering / AI-Assisted Cybersecurity Research"
portfolio. The deliverable must be honest about what it measures.

## 2. The in-posture decision (the one fork Chris chose)

Phase 4's objective leans on "refusal" and "robustness," which in the usual LLM-eval sense
want a **model in the loop** (does the model refuse a harmful prompt? does it follow an
injected instruction? does it hallucinate uncited claims?). This project has **no LLM** — by
design (deterministic/offline/stdlib). So there is a genuine wall: without a generator we
cannot measure *model behavior*.

**Chosen approach: fully in-posture (Option 1).** We measure everything about the
**deterministic pipeline** — grounding, citation accuracy, scope/authz refusal, and
pipeline-level injection/info-disclosure robustness — all offline and deterministic. The
**model-in-the-loop evals are built as a harness + fixtures behind a `Generator` Protocol
seam, marked deferred**, so that when a real generator is wired (Phase 5+ or a dedicated
LLM-eval slice) the same evals run against it unchanged. This keeps the whole project
hermetic/offline/CI-green while still delivering a real benchmark and gate.

### Approaches considered
- **Option 1 — fully in-posture (CHOSEN).** All four weeks deterministic over the existing
  pipeline; model-eval behind the seam, deferred. Trades away a *model*-behavior number today
  for keeping the project's core guarantee (deterministic/offline/hermetic/CI-green) intact.
- **Option 2 — in-posture + a CI-excluded live-LLM eval slice.** Everything in Option 1 plus
  one `-m integration`-style module that, when a local offline model is present, generates
  answers and measures model refusal/hallucination/injection-following; skips otherwise.
  Rejected *for now*: adds a heavy optional dependency + non-determinism; the `Generator` seam
  this phase builds is exactly what makes Option 2 a clean later addition, so nothing is lost
  by deferring it.
- **Option 3 — wire a local LLM as the Phase-4 default.** Rejected: breaks the hermetic/
  stdlib/deterministic guarantee across the whole suite; CI can no longer run evals
  offline-deterministically. This is Phase 5+ territory.

## 3. Goals / non-goals / anti-goals

**Goals**
- Deterministic, offline, hermetic metrics for **grounding**, **citation accuracy**,
  **refusal**, and **pipeline-level robustness**, computed over the real `ResearchService`
  surfaces (no re-implementation of the pipeline in the evaluator).
- A versioned **benchmark of ≥50 labeled items** in a repo format, PUBLIC/synthetic, drawn
  from the existing fixtures + the Week-11 injection corpus, with a methodology write-up.
- **Red-team evals** (prompt-injection + information-disclosure) with **documented acceptance
  thresholds**, failing loudly below threshold.
- A **results report** (self-contained, offline, committed-to-repo artifact) and a
  **pytest-level regression gate** that fails CI if any metric drops below its threshold.
- A **`Generator` Protocol seam + deferred model-eval harness/fixtures**, so model-behavior
  evals (refusal/hallucination/injection-following) are ready to run against a future LLM.

**Non-goals**
- Wiring a real LLM, or measuring any *model* behavior now (built behind the seam, deferred).
- Any network, non-deterministic, or non-hermetic eval in the default suite.
- New heavy runtime dependencies. (stdlib + pydantic only, as the rest of the project.)
- A live/interactive web dashboard or server endpoint. (The report is a static artifact.)

**Anti-goals** (failure even if it "works")
- A metric that scores *vibes*: surface string-overlap passing for grounding, or any metric
  that can be high while an uncited claim ships. **Uncited claims score zero.**
- A benchmark that only exercises happy paths (no DENIED, no NOT_FOUND, no empty, no attack).
- Thresholds so loose they can never catch a regression, or so tied to today's exact strings
  that they break on a benign change.
- **Over-claiming**: calling pipeline-level robustness "model robustness," or implying the
  system measures LLM refusal. Every report line states in-posture scope honestly.
- Introducing non-determinism (ordering, hashing, time) into a metric.

## 4. Constraints

- Python 3.12; **stdlib + pydantic only**; no new runtime deps. (A static HTML report is
  hand-emitted strings — no templating dep.)
- Deterministic / offline / hermetic; default suite stays `-m "not integration"` green.
- PUBLIC / synthetic only; no CUI/classified.
- `ruff check .` (line length 100), `black --check .`, `mypy` all clean.
- The evaluator **calls the real pipeline** (`ResearchService`, `authorize`, `build_report`,
  `AgentToolset`, `malicious_corpus`); it must not duplicate or fork pipeline logic, or it
  would measure a copy, not the system.
- Each slice gated: TDD (RED→GREEN) + fresh opus-xhigh whole-branch review + local merge to
  main. **No push without Chris's explicit go-ahead** (repo is local, no remote).
- Attribution footer on every commit (Claude Opus 4.8 + Claude-Session line).

## 5. What gets built — the four slices

The weeks are coupled: Week 13 defines the metric vocabulary and the labeled-item shape that
Weeks 14–16 consume. One design doc (this file); one plan + branch + review + merge per week.

### Week 13 — Metrics (`evaluation/metrics.py`, replacing the stub)

Replace the `score(predictions, gold)` NotImplementedError stub with deterministic metric
functions over **evaluation records**, not bare strings. An evaluation record is what the
pipeline already returns plus the item's gold labels, so the metric sees outcome + citations,
not a flattened answer string (a bare-string metric could only do surface overlap — an
anti-goal). Proposed record shape (pydantic, frozen):

```
EvalItem:    id:str, kind:Literal["cve","attack","search","authz","injection"],
             query:str, role:str, expected_outcome:Outcome,
             gold_document_ids:frozenset[str], must_not_appear:frozenset[str]=∅, note:str=""
EvalResult:  item:EvalItem, outcome:Outcome, cited_ids:tuple[str,...],
             retrieved_ids:tuple[str,...], answer:str
```

Metrics (each returns a float in [0,1] or a labeled dict; all pure/deterministic):

- **grounding(result)** — of the claims (answer lines) the pipeline emitted, the fraction
  whose citation id is in `retrieved_ids`. Because `build_report` drops uncited lines,
  grounding is 1.0 by construction for an OK answer — the metric's job is to *verify that
  invariant and catch a regression that lets an uncited line through*. An uncited answer line
  ⇒ that claim scores 0 (the ROADMAP's "uncited answers score zero"). grounding and
  citation_accuracy are **defined only over answered (`Outcome.OK`) results**; a no-answer
  outcome (DENIED/NOT_FOUND/empty) is scored by `refusal_correct`, not folded into grounding
  as a free 1.0 (which would dilute the signal). `aggregate` averages grounding/citation over
  the answered subset and refusal over all items, and says so in the report.
- **citation_accuracy(result)** — fraction of `cited_ids` that are in the item's
  `gold_document_ids`. A citation to a non-gold (or non-retrieved) doc lowers it; catches a
  hallucinated or wrong citation. Defined 1.0 when there are no citations and none were
  expected.
- **refusal_correct(result)** — boolean: did `outcome` match `expected_outcome`? Aggregated
  over the benchmark into a refusal-accuracy rate. This is the in-posture meaning of
  "refusal": DENIED for an unauthorized role, NOT_FOUND for absent/out-of-scope, empty-OK for
  a no-match search, and (for injection items) the attack's intended effect not occurring.
- **aggregate(results)** — rolls the per-item metrics into a report dict: per-kind and overall
  grounding, citation_accuracy, refusal_accuracy, and counts. Deterministic ordering.

Per-kind applicability (not every metric applies to every item; `aggregate` reports each
metric only over the kinds it is defined for): **grounding** → `cve`/`attack` (the only kinds
whose `build_report` answer has cited claim-lines; `search` surfaces no body per Week 11);
**citation_accuracy** → `cve`/`attack`/`search` (search's returned ranked ids are its
citations); **refusal_correct** → all kinds; **robustness** (Week 15) → `injection`/`authz`.

Honest-scope docstring: these measure the **pipeline**, not a model; model-behavior metrics
live behind the Week-16 seam and are deferred.

### Week 14 — Benchmark (`evaluation/benchmark.py` + `evaluation/benchmark_items.py`)

A versioned set of **≥50 `EvalItem`s**, PUBLIC/synthetic, authored from the committed fixtures
(NVD/ATT&CK/KEV/Sigma samples) + the Week-11 injection corpus. Proposed composition (≥50):

- CVE id-route: OK (CVE-2021-44228 → its NVD doc), NOT_FOUND (absent id), DENIED (bad role).
- ATT&CK id-route: OK (T1059 etc.), NOT_FOUND (deprecated/absent), DENIED.
- Search: OK-with-gold (query → expected doc ids across sources), empty-OK (no-match query),
  DENIED.
- Authz/ABAC: a RESTRICTED doc → senior sees it; research_analyst gets NOT_FOUND
  (byte-identical to absent) on every path; `must_not_appear` = the secret token.
- Injection: each `malicious_corpus()` doc → the forged/impersonated citation must not surface,
  authz unchanged, body attributed-not-executed.

Items must be **genuine** — a distinct (query, role, expected-outcome) that exercises real
pipeline behavior — never padding to hit the count. The ≥50 floor is reachable from the
corpus via role × query × outcome combinations across four sources + authz + injection; if a
genuine floor ever fell short of 50 I'd raise it with Chris rather than pad (an anti-goal).

A `runner` executes each item against the **real** `ResearchService`/`AgentToolset` and
produces `EvalResult`s. Methodology write-up: `docs/phase4-evaluation-methodology.md` — what
each metric means, in-posture scope, how items were derived, how to reproduce
(`python -m secure_ai_research.evaluation.run`).

### Week 15 — Red-team evals + acceptance criteria (`evaluation/redteam.py`)

Formalize the Week-10/11 security properties into **measured** evals with **documented
thresholds**, over the real pipeline:

- **Injection eval** — run `malicious_corpus()` through the pipeline; robustness = fraction of
  attacks neutralized at pipeline level (no forged citation in output, no authz change, no
  RESTRICTED leak). **Acceptance: 100% (1.0).** Any drop fails.
- **Information-disclosure eval** — the two-user RESTRICTED scenario: across id-route, search,
  and the AgentToolset, `research_analyst` obtains **zero** bytes of RESTRICTED content and a
  response byte-identical to a genuinely-absent id. **Acceptance: 0 disclosures.**
- Thresholds table lives in one place (`evaluation/thresholds.py`) consumed by Week 16.

Proposed thresholds (my call; defensible from the pipeline's deterministic guarantees, strict
because the pipeline is deterministic so there is no noise to tolerate): grounding = 1.0,
citation_accuracy = 1.0, refusal_accuracy = 1.0, injection_robustness = 1.0, info_disclosures
= 0. (A real LLM behind the seam would get *looser, honest* thresholds; these strict ones are
correct precisely because the system is deterministic today.)

### Week 16 — Results report + CI regression gate (`evaluation/report.py`, `evaluation/run.py`)

- **`run.py`** — `python -m secure_ai_research.evaluation.run` executes benchmark + red-team
  evals, prints a deterministic summary, and writes a **self-contained static report** to
  `reports/phase4-eval-report.html` (hand-emitted HTML string, no dep; also a `.md` sibling):
  per-metric score vs threshold, per-kind breakdown, pass/fail, and an explicit "in-posture;
  model-behavior evals deferred (seam present)" banner. The report is a **regenerated-on-run
  artifact** (a date in its header is fine); committing a snapshot is optional and the gate
  never diffs its bytes.
- **Regression gate** — `tests/test_eval_regression_gate.py`: a hermetic pytest that runs the
  benchmark + red-team evals and **asserts every metric value ≥ its threshold** (and
  info_disclosures == 0) — it compares metric *values*, never report file bytes, so a
  benign report-template change can't break CI. Unit-level, deterministic, no network, runs in
  the default suite. Guarded against vacuous pass: it also asserts the benchmark ran a non-zero
  item count per kind.
- **`Generator` seam + deferred model-eval** — a `ports.Generator` Protocol
  (`generate(prompt, passages) -> str`) and a `model_eval` module whose tests are
  `@pytest.mark.skip`/`-m model_eval` (not in default suite), with fixtures from the injection
  corpus, asserting the *shape* of a future model-behavior eval (refusal/hallucination/
  injection-following). Documented as deferred; proves the seam is wired without running an LLM.

## 6. Review focus (input classes the tests must pin)

1. A metric that silently rewards an **uncited answer line** (grounding must score it 0, not
   skip it) — the ROADMAP's load-bearing rule.
2. A **citation to a retrieved-but-wrong doc** (in retrieved set, not in gold) — citation
   accuracy must catch it, not pass it because it was "retrieved."
3. The info-disclosure eval must assert **byte-identical** NOT_FOUND (absent vs
   present-RESTRICTED), not merely "not 200" — a status-only check misses a response oracle.
4. The regression gate must **fail** when a threshold is unmet (prove load-bearing by a
   temporary metric-break RED), not pass vacuously on an empty result set.
5. The gate must be **deterministic** and compare metric *values* (not report bytes), with
   stable ordering, so it neither flaps nor passes vacuously on an empty result set.

## 7. What's left to the builder (per-slice plans)

Exact pydantic field types and metric formulas (pinned above in prose; the Week-13 plan makes
them code + tests), the authored benchmark items (Week-14 plan), the HTML/MD report template
strings (Week-16 plan), and the threshold constants (Week-15 plan, values proposed in §5).

## 8. Calls I made (for Chris to check while reading)

- **Cadence:** same as Phase 2/3 — 4 week-slices run continuously, each with its own
  plan/branch/TDD/opus-xhigh-review/local-merge; I do **not** pause for per-slice approval.
  Only this phase design needs your approval. (Correct me if you want a pause per slice.)
- **"Refusal" in-posture** = the pipeline's deny/absent/empty/attack-neutralized behaviors
  (there is no model to refuse), stated honestly everywhere.
- **Thresholds** = strict (1.0 / zero), because a deterministic pipeline has no noise to
  tolerate; a future LLM gets looser honest thresholds behind the seam.
- **Dashboard** = a committed static HTML+MD report file + a pytest gate, not a server/endpoint
  or a live page — consistent with the offline/in-repo posture.
- **Model-behavior evals** = built behind a `Generator` seam and **deferred** (skipped/
  `-m model_eval`), not run, per your in-posture choice.
- **Benchmark source** = the existing committed fixtures + the Week-11 injection corpus; no new
  external data pulled.
