# Phase 2 — end-to-end CVE-correlation demo design

**Status:** approved by precedent (Chris, 2026-11-19 — "run all phase 2" in-posture batch, per-slice
design-approval pause waived; design decisions below are my calls, recorded for review).
**Slice 4 of 4 (final)** of the in-posture Phase-2 completion batch
(search ✅ → CISA KEV ✅ → Sigma ✅ → **correlation demo**). Closes ROADMAP Week 8's
"end-to-end CVE-correlation demo" line.

## 1. Intent / why

Phase 2 ingested four public sources into one authorize-before-retrieve corpus: NVD (vulnerability),
CISA KEV (known-exploited advisory), MITRE ATT&CK (technique), and SigmaHQ (detection). The payoff is
**correlation**: a single pivot — a CVE or an ATT&CK technique — should pull the *related* evidence
from across those sources in one cited, audited query. This slice delivers a small, runnable,
offline demonstration of exactly that, so a reader can see the pipeline tie a vulnerability to its
known-exploited status and its detection, and a technique to its detections — and can confirm the
audit trail records which sources were correlated.

## 2. Goals

- A runnable, **offline, deterministic, stdlib-only** demo: `python -m secure_ai_research.demo.correlation`
  builds the full in-posture corpus and prints a readable correlation report for two pivots:
  - **CVE-2021-44228** (Log4Shell) → the CISA KEV advisory (known-exploited) **and** the SigmaHQ
    detection rule — one CVE, two independent authoritative sources.
  - **T1059** (Command and Scripting Interpreter) → the MITRE ATT&CK technique(s) **and** the SigmaHQ
    PowerShell detection — one technique, correlated with its detection.
- A pure, testable core: `build_correlation_report(service, pivots) -> str` that runs each pivot
  through the real `ResearchService.search(...)` authorize-before-retrieve path and then keeps the
  retrieved documents that **explicitly reference the pivot identifier** (the correlation criterion —
  see below), grouping them by source (derived from the `document_id` namespace: `KEV-`, `SIGMA-`,
  `T####`, `CVE-`) and rendering a report naming each correlated source. No new retrieval logic — it
  *uses* the slice-1 search service; the reference filter is the demo's analytical selection, not a
  re-ranking.

  **Why a reference filter, not raw top-N:** the in-posture `HashingEmbedder` is a deterministic
  bag-of-words placeholder (a real embedding model is the deferred Ollama line). It ranks the genuine
  correlation at the very top — for `CVE-2021-44228`, the SigmaHQ detection and the CISA KEV advisory;
  for `T1059`, the ATT&CK technique and the SigmaHQ detection — but below those it returns a noisy tail
  of documents sharing only a common token (synthetic `CVE-2099-*`, unrelated KEV entries). Keeping
  only the documents whose retrieved passage contains the pivot identifier is the honest, robust way to
  show *genuine* cross-source correlation without cherry-picking a magic `limit`; empirically it yields
  exactly `{SigmaHQ, CISA KEV}` for the CVE and `{MITRE ATT&CK, SigmaHQ}` for the technique.
- A hermetic test pinning the correlation: the CVE pivot surfaces both a `KEV-` and a `SIGMA-` document;
  the T1059 pivot surfaces both a `T1059` and a `SIGMA-` document; **one audit record is emitted per
  pivot search**, each recording ≥2 `data_source_ids` (the correlation is visible in the audit trail).
- A short walkthrough doc `docs/phase2-correlation-demo.md`, and the delivered in-posture ROADMAP
  Week-5/6/7/8 lines ticked (with the infra-gated lines left unchecked and annotated as deferred).

## 3. Non-goals

- **No LLM / generation.** The demo is retrieval-only correlation (`model_id="retrieval-only"`), in
  keeping with the in-posture decision; no natural-language synthesis of the correlated evidence.
- **No live network.** The demo builds the corpus from the committed fixtures only; NVD live-fetch
  (opt-in `SAIR_ALLOW_LIVE_FETCH`, default off) is **out of scope** — noted in the report/doc as the
  way CVE-2021-44228 would also pull its NVD record, but never exercised in the demo or its test.
- **No new endpoint, no changes** to `ResearchService`, the loaders, the id-routes, `search`,
  `build_report`, `deps`, or any existing module. This slice only *adds* a `demo` package, a test, a
  doc, and ROADMAP edits.
- **No new runtime dependency.** stdlib + the existing package only.

## 4. Anti-goals (a failure even if it "works")

- **A demo that fakes the pipeline** — hand-building citations or hard-coding the correlation instead
  of calling the real `service.search(...)` over the real authorize gate and the assembled corpus.
  The demo must prove the *actual* pipeline correlates, or it proves nothing.
- **A non-deterministic or networked demo** — anything that reaches the network, depends on wall-clock
  ordering, or varies run to run. Must be byte-stable and offline.
- **Scope creep into production code** — refactoring `deps`/`ResearchService` "to share corpus
  building". The demo builds its own offline corpus (the four fixtures) explicitly; a few lines of
  duplication is the deliberate, cheaper choice over coupling the demo to env/cache-bound
  `get_service`. (If a future loader is added, the demo is pinned to this phase's four sources — fine.)

## 5. Constraints

- Python 3.12, stdlib-only at runtime, no new dependency. Deterministic, offline, hermetic test
  (no `@pytest.mark.integration`).
- PUBLIC/synthetic only; uses the already-committed fixtures.
- `ruff`/`black`/`mypy` clean; line length 100. Attribution footer on every commit.
- The demo reuses the existing `ResearchService` / loaders / `authorize` / audit exactly as the app
  wires them, minus live-fetch — it must not reimplement retrieval, ranking, or the authz gate.

## 6. Approaches considered

- **Approach 1 — runnable `demo` package (pure report fn + offline corpus builder + `__main__`),
  pinned by a hermetic test, plus a doc (CHOSEN).** A real artifact a person can run and see, and a
  test that proves the real pipeline correlates. Small, in-posture, no production changes.
- **Approach 2 — test-only demo (a well-documented pytest module, no runnable entry).** Rejected: a
  test that passes is not a *demo* anyone can run to *see* the correlation; the ROADMAP line asks for a
  demonstration, not just coverage.
- **Approach 3 — a live HTTP walkthrough (curl against a running server).** Rejected: not hermetic,
  not deterministic in a test, and needs a running server — out of the offline in-posture envelope.

**Why Approach 1:** it is the only option that is both a genuine, runnable demonstration and a pinned,
hermetic proof that the *real* assembled pipeline correlates across sources — using the slice-1 search
path, not a reimplementation.

## 7. The design (decided)

### 7.1 `src/secure_ai_research/demo/correlation.py`

- `build_offline_corpus(audit_path: Path) -> ResearchService` — constructs `ResearchService(
  HashingEmbedder(), InMemoryVectorStore(), authorize, audit_path)` and indexes the four committed
  fixtures via `nvd.load`, `attack.load`, `kev.load`, `sigma.load` (same incantation as
  `deps.get_service`, minus the env-bound `fetch_missing`). Offline by construction.
- `_source_of(document_id: str) -> str` — maps the id namespace to a human source label: `KEV-*` →
  "CISA KEV (known-exploited)", `SIGMA-*` → "SigmaHQ (detection)", `T<digits>*` → "MITRE ATT&CK
  (technique)", `CVE-*` → "NVD (vulnerability)", else "other".
- `correlate(service: ResearchService, pivot: str) -> dict[str, list[str]]` — `res =
  service.search(pivot, role="research_analyst", limit=_SEARCH_LIMIT)`; keep each citation whose
  `pivot in citation.passage` (the document genuinely references the pivot id); return
  `{_source_of(id): [ids…]}` with ids in retrieval order and sources in sorted order. `pivot` is both
  the search query and the reference token. `_SEARCH_LIMIT = 10` (> corpus size, so every referencing
  document is in the candidate set).
- `build_correlation_report(service, pivots: list[tuple[str, str]]) -> str` — for each `(label, pivot)`
  render a deterministic block: the label, the pivot, and one line per correlated source (`source:
  id1, id2`). Returns the whole report string (the test asserts on it; `main` prints it).
- `main() -> None` / `if __name__ == "__main__":` — create a temp audit file (`tempfile`), build the
  offline corpus, print `build_correlation_report(service, _PIVOTS)` where
  `_PIVOTS = [("Log4Shell", "CVE-2021-44228"), ("Command and Scripting Interpreter", "T1059")]`.
- `role="research_analyst"` is the existing permitted role (the authz gate is real, not bypassed).

### 7.2 `tests/test_correlation_demo.py` (hermetic)

- A unit test of `_source_of` for each namespace (`KEV-…`, `SIGMA-…`, `T1059`, `CVE-…`, unknown).
- `correlate(service, "CVE-2021-44228")` returns exactly `{"CISA KEV (known-exploited)":
  ["KEV-CVE-2021-44228"], "SigmaHQ (detection)": ["SIGMA-3eb91f0a-0060-424a-a676-59f5fdd75610"]}`
  (the two genuinely-correlated sources, no NVD-2099 noise).
- `correlate(service, "T1059")` keeps a `MITRE ATT&CK (technique)` entry containing `T1059` and a
  `SigmaHQ (detection)` entry whose id starts `SIGMA-` (assert presence of both source labels + ids,
  tolerant of whether `T1059.001` is also kept).
- `build_correlation_report(service, _PIVOTS)` contains both pivot labels and, for the CVE pivot,
  `KEV-CVE-2021-44228` + a `SIGMA-` id; for the technique pivot, `T1059` + a `SIGMA-` id.
- Assert `read_records(audit)` has exactly **2** records (one per pivot search), and the CVE pivot's
  record (the one whose `retrieved_doc_ids` contains `KEV-CVE-2021-44228`) has `data_source_ids`
  containing both `"CISA KEV"` and `"Sigma"` (correlation visible in the audit trail). Pins goal + the
  per-analysis-audit ROADMAP line. (The search audit records the full retrieved set, including the
  ranked tail, so the assertion is `⊇ {"CISA KEV", "Sigma"}`, not equality.)

### 7.3 Doc + ROADMAP

- `docs/phase2-correlation-demo.md`: what the demo shows, the two pivots and which sources each
  correlates, how to run it (`python -m secure_ai_research.demo.correlation`) and the test, and the
  in-posture caveats (retrieval-only/no-LLM; NVD via opt-in live-fetch; pgvector/MinIO/Ollama deferred).
- `ROADMAP.md`: tick the **in-posture** Phase-2 lines that are delivered (Week 5 NVD/KEV loaders; Week 6
  ATT&CK/Sigma; Week 7 authorize-before-retrieve + nearest-neighbor within scope; Week 8 cited report +
  live `/research/*` + per-analysis audit + this correlation demo). Leave the infra-gated lines (Week 5
  MinIO/pgvector, Week 6 Ollama/pgvector upsert, Week 7 local generation model) **unchecked** with a
  one-line "deferred — out of in-posture envelope" annotation so the record is honest.

## 8. What is left to the builder

- The exact report string format (headings, bullet style) and the `_source_of` mapping literals.
- The precise test assertions on the report text (substring checks that tolerate formatting).
- The ROADMAP annotation wording for deferred lines.

## 9. Review focus (for the final reviewer)

1. **Real pipeline, not faked** — the demo calls `service.search(...)` over the real authz gate and the
   assembled four-source corpus; citations/correlation are produced by retrieval, not hard-coded.
2. **Determinism / hermeticity** — no network, no wall-clock dependence; the report is byte-stable;
   the test has no `integration` marker and needs no live fetch.
3. **Correlation is genuine** — the CVE pivot really surfaces KEV + Sigma and the T1059 pivot really
   surfaces ATT&CK + Sigma from the committed fixtures (not an artifact of the assertion being too loose).
4. **Zero blast radius** — only a new `demo` package, a test, a doc, and ROADMAP edits; no change to
   `ResearchService`, loaders, routes, `search`, `build_report`, or `deps`.
5. **Honest ROADMAP** — only the genuinely-delivered in-posture lines are ticked; infra-gated lines stay
   unchecked and annotated, so the checklist doesn't overclaim.
