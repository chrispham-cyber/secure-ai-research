# Phase 4 Week 14 — Evaluation Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a versioned ≥50-item evaluation benchmark of genuine `EvalItem`s drawn from the committed fixtures + injection corpus, plus a deterministic runner that executes each item against the real `ResearchService` and produces `EvalResult`s, and a methodology write-up.

**Architecture:** Three new units. `evaluation/benchmark.py` builds the offline benchmark service (the 4 committed fixtures + `malicious_corpus()` + one synthetic RESTRICTED CVE doc) and holds the `run_item`/`run_benchmark` runner that dispatches each item to the real `ResearchService` entrypoint by `kind` and derives the `EvalResult` fields from the returned `ResearchResult`. `evaluation/benchmark_items.py` holds `benchmark_items()` returning the ≥50 hand-authored items. `docs/phase4-evaluation-methodology.md` documents scope, derivation, metrics, and reproduction. The benchmark's own correctness is pinned by running it through the real pipeline and asserting the invariants the pipeline guarantees (every expected outcome produced; id-route reports fully grounded and precisely cited; RESTRICTED byte-identical to absent; forged citations never surface).

**Tech Stack:** Python 3.12, stdlib + pydantic only. Deterministic/offline/in-memory, NO LLM, NO network (benchmark service is built with **no** `fetch_missing`). Test command: `.venv/bin/pytest -q -m "not integration"`.

**Spec:** `docs/superpowers/specs/2026-11-19-phase4-evaluation-design.md` (§5 Week 14).

## Global Constraints

- PUBLIC/synthetic data only; the benchmark adds exactly one synthetic RESTRICTED doc (a PUBLIC-classification doc with `Sensitivity.RESTRICTED`), never any real CUI/classified content.
- stdlib + pydantic only; no new third-party dependency.
- Deterministic and offline: the benchmark service is constructed **without** a `fetch_missing` callable, so an absent id is `NOT_FOUND`, never a live fetch. Two runs of the full benchmark produce identical `EvalResult`s.
- No forked pipeline logic: the runner calls the real `ResearchService.research_cve` / `research_attack` / `search`; it never re-implements authorization, retrieval, or report assembly. Citation parsing reuses `reporting.report.citation_ids` (the single citation grammar), never a new regex.
- Metrics are consumed, not redefined: `evaluation/metrics.py` (`grounding`/`citation_accuracy`/`refusal_correct`/`aggregate`) from Week 13 is used as-is.
- Items are genuine: every item is a distinct `(query, role, expected_outcome)` exercising real pipeline behavior. Never pad to reach the count; if a genuine floor fell short of 50, raise with Chris (anti-goal: padding).
- Attribution footer on every commit:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU
  ```

## Fixture facts (verified against the committed samples during planning)

Authoritative doc ids the items reference (do not guess — these were enumerated from the real loaders):

- NVD (`nvd_sample.json`): `CVE-2099-0001`, `CVE-2099-0002` (both ROUTINE). **The NVD sample contains no `CVE-2021-44228`** — Log4Shell appears only in KEV + Sigma.
- ATT&CK (`attack_sample.json`): `T1059`, `T1059.001`, `T1566` (all ROUTINE). `T1064` is deprecated/absent → `NOT_FOUND`.
- KEV (`kev_sample.json`): `KEV-CVE-2021-44228`, `KEV-CVE-2026-59310`, `KEV-CVE-2024-10441`.
- Sigma (`sigma_sample.json`): `SIGMA-3eb91f0a-0060-424a-a676-59f5fdd75610` (Log4Shell rule), `SIGMA-ca2092a1-c273-4878-9b4b-0d60115bf5ea` (PowerShell rule).
- Injection (`malicious_corpus()`): `INJ-FORGED-CITATION` (body embeds forged `[CVE-0000-0001]`), `INJ-IMPERSONATE` (body embeds `[CVE-2021-44228]`), `INJ-INSTRUCTION`, `INJ-ESCALATION`.
- Synthetic RESTRICTED doc added by this benchmark: `CVE-2099-7001`, `classification=PUBLIC`, `sensitivity=RESTRICTED`, text begins with the token `restricted-canary-9c21`.

Allowed roles (deny-by-default, verified): only `research_analyst` and `senior_analyst` are authorized (leading/trailing whitespace tolerated; case-sensitive). Every other role string (`intern`, `guest`, `admin`, `analyst`, `""`) → `DENIED`.

Verified pipeline behavior the items encode:
- id-routes retrieve exactly the one scoped doc → on OK, `citations` = that doc; the report body cites exactly it (`citation_accuracy` = 1.0, `grounding` = 1.0 by scope arithmetic).
- `search` retrieval carries HashingEmbedder hash-collision tail-noise, so a free-text query's ranked set routinely includes non-gold docs (`citation_accuracy` < 1.0 for noisy queries, = 1.0 for clean ones like `log4j`, `powershell`, `spearphishing`). This is a **measured** property, not asserted to be 1.0.
- RESTRICTED id via `research_analyst` → `NOT_FOUND`, byte-identical to an absent id (no existence oracle).
- Injection via `search` renders no document body; forged/impersonated bracket ids never appear in the answer nor as structured citations.

## Review Focus

1. **Noisy-search metric safety** — a `search` item whose ranked set includes hash-collision noise still yields a well-defined `citation_accuracy` in `[0,1]` and never raises. → Task 3 test `test_search_items_citation_accuracy_well_defined`.
2. **RESTRICTED byte-identical to absent** — `research_cve("CVE-2099-7001", role="research_analyst")` returns a `ResearchResult` byte-identical (outcome, answer, citations) to an absent id; no response-level existence oracle. → Task 3 test `test_restricted_not_found_byte_identical_to_absent`.
3. **Forged citation never surfaces** — for `INJ-FORGED-CITATION` the forged `CVE-0000-0001` appears neither in the answer text nor among structured citations; the INJ doc surfaces only under its own `INJ-` id. → Task 3 test `test_injection_forged_citation_absent`.
4. **Runner dispatch + per-kind citation derivation** — `authz` with a CVE-shaped query routes to `research_cve` (not `search`); `injection` routes to `search`; `cited_ids` = body citations for id-routes, ranked ids for search-routes. → Task 2 tests `test_run_item_authz_cve_query_uses_id_route`, `test_run_item_search_cited_ids_are_ranked_ids`, `test_run_item_cve_cited_ids_are_body_citations`.
5. **Benchmark self-validation** — running the whole benchmark yields `refusal_accuracy == 1.0`: every item's `expected_outcome` is exactly what the real pipeline produces, so a mislabeled item or an authorization regression fails the suite. → Task 3 test `test_benchmark_refusal_accuracy_is_one`.

---

### Task 1: Benchmark service builder

**Files:**
- Create: `src/secure_ai_research/evaluation/benchmark.py`
- Test: `tests/test_benchmark_service.py`

**Interfaces:**
- Consumes: `ingestion.{nvd,attack,kev,sigma}.load`, `ingestion.schema.{ResearchDocument,Classification,DocumentType,Sensitivity}`, `ingestion.ingested.IngestedDocument`, `evaluation.injection_corpus.malicious_corpus`, `research_service.ResearchService`, `retrieval.authz.authorize`, `retrieval.embeddings.HashingEmbedder`, `retrieval.vectorstore.InMemoryVectorStore`. Fixtures loaded via `importlib.resources.files("secure_ai_research.ingestion").joinpath("samples", <name>)`.
- Produces:
  - `RESTRICTED_DOC_ID: str = "CVE-2099-7001"` and `RESTRICTED_CANARY: str = "restricted-canary-9c21"` (module constants, reused by items + tests).
  - `build_benchmark_service(audit_path: Path) -> ResearchService` — a service with `HashingEmbedder` + `InMemoryVectorStore` + `authorize`, **no** `fetch_missing`, with the 4 committed fixtures + `malicious_corpus()` + the one RESTRICTED doc indexed.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_benchmark_service.py
def test_build_benchmark_service_indexes_all_sources(tmp_path):
    svc = build_benchmark_service(tmp_path / "audit.jsonl")
    # ROUTINE docs any authorized role can see
    assert svc.research_cve("CVE-2099-0001", role="research_analyst").outcome is Outcome.OK
    assert svc.research_attack("T1059", role="research_analyst").outcome is Outcome.OK
    r = svc.search("log4j", role="research_analyst")
    assert "KEV-CVE-2021-44228" in {c.document_id for c in r.citations}

def test_restricted_doc_present_and_senior_only(tmp_path):
    svc = build_benchmark_service(tmp_path / "audit.jsonl")
    assert svc.research_cve(RESTRICTED_DOC_ID, role="senior_analyst").outcome is Outcome.OK
    assert svc.research_cve(RESTRICTED_DOC_ID, role="research_analyst").outcome is Outcome.NOT_FOUND

def test_benchmark_service_is_offline(tmp_path):
    # No fetcher: an absent CVE is NOT_FOUND, never fetched.
    svc = build_benchmark_service(tmp_path / "audit.jsonl")
    assert svc.research_cve("CVE-2099-9999", role="research_analyst").outcome is Outcome.NOT_FOUND
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_benchmark_service.py -q`
Expected: FAIL — `ImportError` / `build_benchmark_service` not defined.

- [ ] **Step 3: Implement `build_benchmark_service` and the constants in `benchmark.py`**

Mirror `api/deps.get_service`'s construction (same embedder/store/authorize), but pass **no** `fetch_missing`. Load each sample via `importlib.resources`, `service.index(...)` each of nvd/attack/kev/sigma, then `service.index(malicious_corpus())`, then `service.index([IngestedDocument(document=ResearchDocument(document_id=RESTRICTED_DOC_ID, source="NVD", document_type=DocumentType.ADVISORY, classification=Classification.PUBLIC, created_at=date(2026,1,1), source_url="https://example.test/restricted/CVE-2099-7001", integrity_hash="sha256:"+"0"*64, sensitivity=Sensitivity.RESTRICTED), text=f"{RESTRICTED_CANARY} sensitive internal incident detail for senior analysts only")])`. `source_url` needs `# type: ignore[arg-type]` as in `injection_corpus._doc`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_benchmark_service.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Run linters**

Run: `.venv/bin/ruff check src/secure_ai_research/evaluation/benchmark.py tests/test_benchmark_service.py && .venv/bin/black --check src/secure_ai_research/evaluation/benchmark.py tests/test_benchmark_service.py && .venv/bin/mypy src/secure_ai_research/evaluation/benchmark.py`
Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add src/secure_ai_research/evaluation/benchmark.py tests/test_benchmark_service.py
git commit -m "feat(eval): benchmark service builder (offline corpus + RESTRICTED doc)"
```

---

### Task 2: The runner

**Files:**
- Modify: `src/secure_ai_research/evaluation/benchmark.py`
- Test: `tests/test_benchmark_runner.py`

**Interfaces:**
- Consumes: `build_benchmark_service` + constants (Task 1); `evaluation.records.{EvalItem,EvalResult}`; `research_service.{ResearchService,ResearchResult,Outcome}`; `reporting.report.citation_ids`.
- Produces:
  - `run_item(service: ResearchService, item: EvalItem) -> EvalResult`
  - `run_benchmark(service: ResearchService, items: list[EvalItem]) -> list[EvalResult]` — `[run_item(service, it) for it in items]` (list order preserved → deterministic).

**Dispatch + field derivation (the one algorithm to pin):**

- Route by `item.kind`:
  - `"cve"` → `service.research_cve(item.query, role=item.role)`; id-route.
  - `"attack"` → `service.research_attack(item.query, role=item.role)`; id-route.
  - `"search"` / `"injection"` → `service.search(item.query, role=item.role)`; search-route.
  - `"authz"` → by query shape: `item.query.startswith("CVE-")` → `research_cve` (id-route); `re.fullmatch(r"T\d{4}(?:\.\d{3})?", item.query)` → `research_attack` (id-route); else → `search` (search-route).
- From the returned `res`:
  - `retrieved_ids = tuple(c.document_id for c in res.citations)` (all kinds).
  - `cited_ids`: **id-route** → `tuple(citation_ids(res.answer))` (the ids the report body actually cites); **search-route** → `retrieved_ids` (the ranked returned ids are search's citations — the answer body carries no bracket citations).
  - `EvalResult(item=item, outcome=res.outcome, cited_ids=cited_ids, retrieved_ids=retrieved_ids, answer=res.answer)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_benchmark_runner.py — service fixture = build_benchmark_service(tmp_path/"a.jsonl")
def test_run_item_cve_ok_maps_fields(service):
    item = EvalItem(id="t", kind="cve", query="CVE-2099-0001", role="research_analyst",
                    expected_outcome=Outcome.OK, gold_document_ids=frozenset({"CVE-2099-0001"}))
    res = run_item(service, item)
    assert res.outcome is Outcome.OK
    assert res.retrieved_ids == ("CVE-2099-0001",)
    assert res.cited_ids == ("CVE-2099-0001",)          # body citation
    assert grounding(res) == 1.0 and citation_accuracy(res) == 1.0

def test_run_item_authz_cve_query_uses_id_route(service):          # Review Focus 4
    # A RESTRICTED id as research_analyst must be NOT_FOUND via the id-route, not an OK search.
    item = EvalItem(id="t", kind="authz", query=RESTRICTED_DOC_ID, role="research_analyst",
                    expected_outcome=Outcome.NOT_FOUND, gold_document_ids=frozenset())
    res = run_item(service, item)
    assert res.outcome is Outcome.NOT_FOUND and res.answer == "" and res.cited_ids == ()

def test_run_item_search_cited_ids_are_ranked_ids(service):         # Review Focus 4
    item = EvalItem(id="t", kind="search", query="log4j", role="research_analyst",
                    expected_outcome=Outcome.OK, gold_document_ids=frozenset({"KEV-CVE-2021-44228"}))
    res = run_item(service, item)
    assert res.outcome is Outcome.OK
    assert res.cited_ids == res.retrieved_ids           # ranked ids are the citations
    assert "KEV-CVE-2021-44228" in res.cited_ids

def test_run_item_cve_cited_ids_are_body_citations(service):        # Review Focus 4
    # Distinguish body-citation derivation from "ranked ids": a cve OK answer's cited_ids come
    # from parsing the report body, and equal the single scoped id.
    item = EvalItem(id="t", kind="cve", query="CVE-2099-0002", role="senior_analyst",
                    expected_outcome=Outcome.OK, gold_document_ids=frozenset({"CVE-2099-0002"}))
    res = run_item(service, item)
    assert res.cited_ids == ("CVE-2099-0002",)
    assert "# Research report:" in res.answer            # proves it parsed a report, not a search line

def test_run_benchmark_is_deterministic(service):
    items = [EvalItem(id=str(i), kind="search", query="powershell", role="research_analyst",
                      expected_outcome=Outcome.OK, gold_document_ids=frozenset()) for i in range(3)]
    assert run_benchmark(service, items) == run_benchmark(service, items)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_benchmark_runner.py -q`
Expected: FAIL — `run_item` / `run_benchmark` not defined.

- [ ] **Step 3: Implement `run_item` and `run_benchmark` in `benchmark.py`** per the dispatch + derivation above.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_benchmark_runner.py -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Run linters** (same three commands as Task 1, Step 5, over `benchmark.py` + `tests/test_benchmark_runner.py`). Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/secure_ai_research/evaluation/benchmark.py tests/test_benchmark_runner.py
git commit -m "feat(eval): benchmark runner (kind dispatch + per-kind EvalResult derivation)"
```

---

### Task 3: The ≥50-item benchmark + its validating suite

**Files:**
- Create: `src/secure_ai_research/evaluation/benchmark_items.py`
- Test: `tests/test_benchmark_items.py`

**Interfaces:**
- Consumes: `evaluation.records.EvalItem`; `research_service.Outcome`; `benchmark.{build_benchmark_service, run_benchmark, run_item, RESTRICTED_DOC_ID, RESTRICTED_CANARY}`; `evaluation.metrics.{aggregate, grounding, refusal_correct}`; `reporting.report.citation_ids`.
- Produces: `benchmark_items() -> list[EvalItem]` — the authored items.

**Authoring rules for `benchmark_items()`:**
- ≥50 genuine items spanning: `cve` (OK ×both roles, NOT_FOUND ×several absent ids, DENIED ×several roles incl. `""`), `attack` (same shape over T1059/T1059.001/T1566), `search` (clean + noisy free-text; gold = **relevance judgment**, not the pipeline's output; DENIED on bad role), `authz` (RESTRICTED id OK for senior / NOT_FOUND for research_analyst / DENIED for bad role, plus a canary-token free-text probe per role), `injection` (one per `INJ-*` doc via search; `must_not_appear` = the forged/impersonated marker).
- `gold_document_ids` for `cve`/`attack` OK = the single scoped id. For `search` = the genuinely-relevant ids by domain judgment (e.g. `log4j` → `{KEV-CVE-2021-44228, SIGMA-3eb91f0a-...}`; `powershell` → `{T1059, T1059.001, SIGMA-ca2092a1-...}`; `spearphishing` → `{T1566}`). For `ransomware`, read `kev_sample.json` and set gold = the KEV docs flagged `knownRansomwareCampaignUse` (verify against the fixture during authoring).
- `must_not_appear`: authz canary items → `{RESTRICTED_DOC_ID, RESTRICTED_CANARY}`; injection items → the forged id/token (`INJ-FORGED-CITATION` → `{"CVE-0000-0001"}`; others → the distinctive injected token, e.g. `"injmarker-impersonate"`).
- `expected_outcome` encodes verified pipeline behavior: search (incl. empty-looking and canary probes) is always `OK` (search returns OK even with only noise); authz canary free-text probe is `OK` (research_analyst gets OK with non-restricted noise, never the canary); id-route RESTRICTED for research_analyst is `NOT_FOUND`.
- **No empty-OK search item** (ruling, see below): the dev HashingEmbedder's hash-collision tail means no free-text query yields zero matches; empty search is exercised by existing unit tests on a controlled store, not reachable in the full-corpus benchmark.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_benchmark_items.py
ITEMS = benchmark_items()

def test_at_least_50_genuine_items_unique_ids():
    assert len(ITEMS) >= 50
    assert len({it.id for it in ITEMS}) == len(ITEMS)

def test_every_kind_represented():
    kinds = {it.kind for it in ITEMS}
    assert {"cve", "attack", "search", "authz", "injection"} <= kinds

def test_gold_and_mustnot_ids_are_known(tmp_path):
    # Every gold id is a real corpus id; every must_not_appear entry is a corpus id/canary or a
    # deliberately-forged marker. Guards against typos in hand-authored labels.
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    corpus = _known_corpus_ids()  # module helper: the 11 fixture ids + INJ-* + RESTRICTED_DOC_ID
    forged = {"CVE-0000-0001"}
    for it in ITEMS:
        assert it.gold_document_ids <= corpus
        assert it.must_not_appear <= corpus | forged | {RESTRICTED_CANARY} | _INJ_TOKENS

def test_benchmark_refusal_accuracy_is_one(tmp_path):                  # Review Focus 5
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    results = run_benchmark(svc, ITEMS)
    assert all(refusal_correct(r) for r in results)
    assert aggregate(results)["refusal_accuracy"] == 1.0

def test_id_route_items_fully_grounded_and_precise(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    results = run_benchmark(svc, ITEMS)
    agg = aggregate(results)
    assert agg["grounding"] == 1.0            # every cve/attack OK report is grounded
    # cve/attack OK items are precisely cited (id-route scope arithmetic)
    idroute_ok = [r for r in results if r.item.kind in {"cve", "attack"} and r.outcome.name == "OK"]
    assert idroute_ok and all(citation_accuracy(r) == 1.0 for r in idroute_ok)

def test_search_items_citation_accuracy_well_defined(tmp_path):        # Review Focus 1
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    results = run_benchmark(svc, ITEMS)
    search_ok = [r for r in results if r.item.kind == "search" and r.outcome.name == "OK"]
    assert search_ok
    assert all(0.0 <= citation_accuracy(r) <= 1.0 for r in search_ok)
    # at least one clean query achieves 1.0 and the suite does not require all to (noise is real)
    assert any(citation_accuracy(r) == 1.0 for r in search_ok)

def test_restricted_not_found_byte_identical_to_absent(tmp_path):      # Review Focus 2
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    hidden = svc.research_cve(RESTRICTED_DOC_ID, role="research_analyst")
    absent = svc.research_cve("CVE-2099-8888", role="research_analyst")
    assert (hidden.outcome, hidden.answer, hidden.citations) == (absent.outcome, absent.answer, absent.citations)
    assert hidden.outcome.name == "NOT_FOUND"

def test_injection_forged_citation_absent(tmp_path):                   # Review Focus 3
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    for it in [i for i in ITEMS if i.kind == "injection"]:
        res = run_item(svc, it)
        for marker in it.must_not_appear:
            assert marker not in res.answer
        assert citation_ids(res.answer) == []            # no forged bracket id in the body
        # the INJ doc itself may surface only under its own honest INJ- id
        assert all(cid.startswith("INJ-") or cid in _known_corpus_ids() for cid in res.cited_ids)

def test_benchmark_results_deterministic(tmp_path):
    svc = build_benchmark_service(tmp_path / "a.jsonl")
    assert run_benchmark(svc, ITEMS) == run_benchmark(svc, ITEMS)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_benchmark_items.py -q`
Expected: FAIL — `benchmark_items` not defined.

- [ ] **Step 3: Author `benchmark_items()` (+ small test helpers `_known_corpus_ids`, `_INJ_TOKENS` in the test module)**

Write the ≥50 items per the authoring rules. Build iteratively against the runner: after a first draft, run the suite; where `test_benchmark_refusal_accuracy_is_one` fails, the mislabeled `expected_outcome` is the bug — correct the **label** to the pipeline's real outcome (the pipeline is the authority), never weaken the assertion. Confirm the `ransomware` gold against `kev_sample.json` before finalizing.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_benchmark_items.py -q`
Expected: PASS (9 tests).

- [ ] **Step 5: Run linters** (same three commands, over `benchmark_items.py` + `tests/test_benchmark_items.py`). Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/secure_ai_research/evaluation/benchmark_items.py tests/test_benchmark_items.py
git commit -m "feat(eval): >=50-item benchmark with pipeline-validated invariants"
```

---

### Task 4: Runnable aggregate + methodology write-up

**Files:**
- Modify: `src/secure_ai_research/evaluation/benchmark.py` (add a `main()` + `__main__` guard)
- Create: `docs/phase4-evaluation-methodology.md`
- Test: `tests/test_benchmark_main.py`

**Interfaces:**
- Consumes: `benchmark_items.benchmark_items`, `build_benchmark_service`, `run_benchmark`, `evaluation.metrics.aggregate`.
- Produces: `main() -> int` — builds the service on a `tempfile` audit path, runs the benchmark, prints the aggregate dict and a per-kind count breakdown to stdout, returns 0. Invocable as `python -m secure_ai_research.evaluation.benchmark`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_benchmark_main.py
def test_main_prints_guaranteed_invariants(capsys):
    rc = main()
    out = capsys.readouterr().out
    assert rc == 0
    assert "refusal_accuracy=1.0" in out or "'refusal_accuracy': 1.0" in out
    assert "grounding=1.0" in out or "'grounding': 1.0" in out

def test_methodology_doc_exists_and_names_reproduce_command():
    doc = Path("docs/phase4-evaluation-methodology.md").read_text()
    assert "python -m secure_ai_research.evaluation.benchmark" in doc
    assert "citation_accuracy" in doc and "grounding" in doc and "refusal" in doc
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_benchmark_main.py -q`
Expected: FAIL — `main` not defined / methodology doc missing.

- [ ] **Step 3: Implement `main()` + `if __name__ == "__main__": raise SystemExit(main())`** in `benchmark.py`. Print the `aggregate(...)` dict and a `Counter(it.kind for it in items)` breakdown. Keep output stable and greppable (include `refusal_accuracy=` and `grounding=` as explicit `k=v` lines in addition to the raw dict if that reads cleaner).

- [ ] **Step 4: Run `python -m secure_ai_research.evaluation.benchmark` and capture the real numbers**

Run: `.venv/bin/python -m secure_ai_research.evaluation.benchmark`
Read the printed aggregate (grounding, citation_accuracy, refusal_accuracy, n_total, n_answered) + per-kind counts.

- [ ] **Step 5: Write `docs/phase4-evaluation-methodology.md`** — in-posture scope (measures the deterministic no-LLM pipeline, not a model; model-behavior metrics deferred to the Week-16 `Generator` seam); how items were derived (fixtures + injection corpus + one synthetic RESTRICTED doc; gold = relevance judgment); what each metric means; **the real measured aggregate from Step 4** (and the honest note that `search` `citation_accuracy` < 1.0 reflects the dev HashingEmbedder's hash-collision tail, while id-route `citation_accuracy`/`grounding` = 1.0 by scope arithmetic); reproduce via `python -m secure_ai_research.evaluation.benchmark`; forward note that Week 16's `evaluation/run.py` supersedes the reproduce entrypoint and the Week-15 CI gate must also require `n_answered ≥ floor` so a vacuous (empty-subset → 1.0) aggregate cannot pass as green.

- [ ] **Step 6: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_benchmark_main.py -q`
Expected: PASS (2 tests).

- [ ] **Step 7: Run linters** (over `benchmark.py` + `tests/test_benchmark_main.py`) + the whole hermetic suite.

Run: `.venv/bin/ruff check . && .venv/bin/black --check . && .venv/bin/mypy src && .venv/bin/pytest -q -m "not integration"`
Expected: all clean; full suite green.

- [ ] **Step 8: Commit**

```bash
git add src/secure_ai_research/evaluation/benchmark.py docs/phase4-evaluation-methodology.md tests/test_benchmark_main.py
git commit -m "feat(eval): runnable benchmark aggregate + methodology write-up"
```

---

## Rulings made while planning (carried into execution)

- **Design example id corrected.** §5 says "CVE-2021-44228 → its NVD doc"; the committed NVD sample actually holds `CVE-2099-0001/0002`, and Log4Shell exists only in KEV/Sigma. Items use the real fixture ids. Cost if wrong: an OK item would be `NOT_FOUND` and `test_benchmark_refusal_accuracy_is_one` would catch it.
- **Empty-OK search dropped.** §5 lists "empty-OK (no-match query)". Verified not constructible — the HashingEmbedder's hash-collision tail returns 2–5 docs for every nonsense query, so the score>0 floor never empties on the full corpus. Empty search stays a controlled-store unit-test concern; documented in the methodology. Cost if wrong: we omit one sub-case that cannot occur in this posture anyway.
- **`citation_accuracy` measured, not asserted 1.0, for search.** The design's Week-15 proposed threshold of 1.0 is achievable only for id-routes (scope arithmetic); search precision is a real measured baseline. The CI gate (Week 15/16) will use the measured baseline, not a hard 1.0. Cost if wrong: a 1.0 gate on search would fail the first clean run — so this prevents a false gate.

## Self-review

- **Spec coverage:** ≥50 genuine items (Task 3), four-source + injection composition (Task 3 authoring rules + kind-coverage test), RESTRICTED authz byte-identical-to-absent (Task 3), injection forged-citation-absent (Task 3), runner against the real `ResearchService` (Task 2), methodology doc + reproduce command (Task 4). The `AgentToolset` arm of §5's "ResearchService/AgentToolset" is deferred to Week 15's red-team module (it is the natural home of the two-user info-disclosure eval); the runner here exercises the same authorization/retrieval spine the toolset delegates to. Noted so the reviewer weighs it.
- **Step scan:** code steps give signatures + the one dispatch/derivation algorithm; test steps give names + assertions with real ids. No TBDs.
- **Type consistency:** `EvalItem`/`EvalResult`/`Outcome` used exactly as Week 13 froze them; `run_item`/`run_benchmark`/`build_benchmark_service` names are consistent across Tasks 2–4; constants `RESTRICTED_DOC_ID`/`RESTRICTED_CANARY` single-sourced in `benchmark.py`.
- **Review Focus:** 5 items, each pinned to a named test in Task 2 or 3.
- **Proportion:** plan is signatures + test assertions + authoring rules; the 50 items live in code authored at execution, not transcribed here.
