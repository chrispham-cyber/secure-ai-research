# Phase 4 Evaluation Methodology (Week 14 benchmark)

This document describes the evaluation benchmark for the Secure AI Research platform: what it
measures, how its items were derived, and how to reproduce the numbers.

## In-posture scope — what is measured

The platform has **no generation model** in this posture. Every metric here measures the
**deterministic, offline retrieve→authorize→assemble pipeline** — `ResearchService` + the
`authorize` ABAC gate + `build_report` — not a language model. "Refusal" is the pipeline's own
deny / not-found decision, not a model declining to answer.

Model-behavior evaluation (does a generator follow injected instructions, does it hallucinate
beyond its citations) is **deferred behind the Week-16 `Generator` Protocol seam**. The Week-11
injection corpus is already the ready-made input for that future eval; here it is used to show
the *pipeline* never renders a poisoned document's body or surfaces its forged citations.

Everything runs on **PUBLIC/synthetic data only**, stdlib + pydantic, in-memory, no network.

## The corpus

`build_benchmark_service` indexes, into a `HashingEmbedder` + in-memory vector store with the
deny-by-default `authorize` gate and **no** live-fetch callable (fully offline):

- the four committed sample fixtures — NVD (`CVE-2099-0001/0002`), MITRE ATT&CK
  (`T1059`, `T1059.001`, `T1566`), CISA KEV (`KEV-CVE-2021-44228`, `KEV-CVE-2026-59310`,
  `KEV-CVE-2024-10441`), SigmaHQ (a Log4Shell rule and a PowerShell rule);
- the Week-11 synthetic injection corpus (`INJ-FORGED-CITATION`, `INJ-IMPERSONATE`,
  `INJ-INSTRUCTION`, `INJ-ESCALATION`);
- one synthetic **RESTRICTED** document `CVE-2099-7001` (PUBLIC classification, `RESTRICTED`
  within-PUBLIC sensitivity), carrying a canary token, visible only to `senior_analyst`.

## How items were derived

The benchmark is **51 genuine `EvalItem`s** (`benchmark_items()`), each a distinct
`(query, role, expected_outcome)` that exercises real pipeline behavior — never padding to reach
a count. Composition:

| kind | n | what it exercises |
|------|---|-------------------|
| `cve` | 13 | CVE id-route: OK (both roles, whitespace-tolerant role), NOT_FOUND (absent ids), DENIED (bad roles incl. anonymous) |
| `attack` | 12 | ATT&CK id-route: OK, NOT_FOUND (deprecated/absent techniques), DENIED |
| `search` | 15 | free-text search: clean + noisy queries across all sources, DENIED on bad role |
| `authz` | 6 | the RESTRICTED doc — senior sees it, research_analyst gets NOT_FOUND, bad role DENIED; plus canary-token search probes per role |
| `injection` | 5 | each injection doc retrieved via search; forged/impersonated citations must not surface |

**Gold labels are relevance judgments** — what a query is genuinely *about* — authored
independently of what the retriever returns, so `citation_accuracy` measures the retriever rather
than restating it. For the id-routes, gold is the single scoped id. For search, gold is the
genuinely-relevant ids across sources (e.g. `log4j` → `{KEV-CVE-2021-44228, SIGMA-<log4shell>}`).

The runner (`run_item` / `run_benchmark`) dispatches each item to the real pipeline entrypoint by
`kind` (and, for `authz`, by the query's id-shape) and derives the `EvalResult`: `retrieved_ids`
from the pipeline's citations, and `cited_ids` from the assembled report body for id-routes or
from the ranked returned ids for search. It never re-implements authorization, retrieval, or
report assembly.

## The metrics

- **grounding** — of an answer's claim lines, the fraction whose every citation id was actually
  retrieved. Averaged over answered `cve`/`attack` items.
- **citation_accuracy** — of the ids the pipeline cited, the fraction that are gold (relevant).
  Averaged over answered `cve`/`attack`/`search` items.
- **refusal_accuracy** — the fraction of all items whose outcome matched the expected outcome.
- **n_total / n_answered** — item counts (answered = produced `OK`).

`authz` and `injection` items are deliberately **excluded from grounding and citation_accuracy**
(their gold is not a citation-quality judgment); they are scored by `refusal_accuracy` and by the
leak-/robustness-invariant tests.

## Measured baseline

Reproduce with:

```
python -m secure_ai_research.evaluation.benchmark
```

Current result (deterministic):

```
benchmark: 51 items | by kind: {'cve': 13, 'attack': 12, 'search': 15, 'authz': 6, 'injection': 5}
  grounding=1.0
  citation_accuracy=0.7742424242424243
  refusal_accuracy=1.0
  n_total=51.0
  n_answered=30.0
```

**Reading the numbers (honest scope):**

- `grounding == 1.0` and `refusal_accuracy == 1.0` are **guaranteed invariants**, pinned by the
  test suite. Every id-route report cites only retrieved ids, and every item's expected outcome
  is exactly what the pipeline produces (a mislabeled item or an authorization regression fails
  `test_benchmark_refusal_accuracy_is_one`).
- `citation_accuracy ≈ 0.77` is a **measured** value, not an invariant. It is **1.0 for the
  id-routes** by scope arithmetic (`research_cve`/`research_attack` retrieve exactly the one
  scoped document). It is **below 1.0 for free-text `search`** because the in-posture
  `HashingEmbedder` has a hash-collision tail: a query's ranked set routinely includes a few
  non-gold documents. Clean queries (`log4j`, `powershell`, `spearphishing`) still score 1.0.
  This is a real property of the deterministic dev embedder, which the deferred production
  embedder (Phase 5) is expected to improve; the benchmark reports it rather than hiding it.

## Deliberate omissions and rulings

- **No "empty-OK" search item.** A truly empty free-text result is not constructible on the full
  corpus — the `HashingEmbedder`'s hash-collision tail returns a few documents for *every*
  query, so the `score > 0` floor never empties. Empty search stays a controlled-store unit-test
  concern (it is covered where the query genuinely shares no hashed dimension with any document).
- **`citation_accuracy` is measured, not asserted `== 1.0`.** A Week-15 CI gate on search
  citation accuracy must use this measured baseline, not a hard 1.0, or it would fail on the
  first clean run.
- **Search-path info-disclosure assertion is deferred to Week 15.** The canary-token search
  items prove, by outcome, that `research_analyst` gets `OK`-with-noise rather than the RESTRICTED
  document; the explicit *no-leak* assertion (the RESTRICTED id/canary never appears in a
  research_analyst result) lands in the Week-15 red-team info-disclosure eval. The id-route
  RESTRICTED path is already proven byte-identical to an absent id here.

## Forward notes (Weeks 15–16)

- Week 16 adds `evaluation/run.py` as the canonical reproduce entrypoint (it supersedes
  `python -m secure_ai_research.evaluation.benchmark` for the full report), plus a CI regression
  gate.
- The CI gate must assert each metric against the **measured baseline** **and** require
  `n_answered ≥ floor` (and a non-zero item count per kind). The `aggregate` empty-subset
  convention scores a missing subset `1.0` (vacuous), so a green aggregate over zero answered
  items must never pass as a healthy result.
