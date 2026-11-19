# Phase 4 Week 13 — Evaluation Metrics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `evaluation/metrics.py` stub with deterministic, pipeline-grounded metrics — `grounding`, `citation_accuracy`, `refusal_correct`, `aggregate` — over typed `EvalItem`/`EvalResult` records.

**Architecture:** Pydantic frozen records carry the real pipeline's output (`Outcome`, citations, answer) plus an item's gold labels; metrics are pure, deterministic functions over those records. The citation grammar is single-sourced from `reporting.report` so the metric measures exactly the citation semantics the pipeline renders — never a forked copy.

**Tech Stack:** Python 3.12, pydantic v2, stdlib; pytest.

**Spec:** `docs/superpowers/specs/2026-11-19-phase4-evaluation-design.md` (§5 Week 13; §6 review focus).

## Global Constraints

- Python 3.12; **stdlib + pydantic only**; no new runtime deps.
- Deterministic / offline / hermetic; default suite `.venv/bin/pytest -q -m "not integration"` stays green.
- PUBLIC / synthetic only.
- `.venv/bin/ruff check .` (line length 100), `.venv/bin/black --check .`, `.venv/bin/mypy` all clean.
- **No forked pipeline logic:** the metric reuses `reporting.report`'s citation grammar, never a re-declared regex.
- `grounding`/`citation_accuracy` are defined over **answered (`Outcome.OK`) results only**; refuse outcomes are scored by `refusal_correct`.
- Metrics are deterministic; `aggregate` uses stable ordering and must not divide by zero.
- Attribution footer on every commit (Claude Opus 4.8 + Claude-Session). **No push without Chris's explicit go-ahead.**

## Review Focus

1. An **uncited body line** in an OK answer must score **0** in `grounding` (counted, not skipped) — the ROADMAP's "uncited answers score zero". → Task 3.
2. A citation to a **retrieved-but-non-gold** doc must **lower** `citation_accuracy`, not pass because the doc was retrieved. → Task 4.
3. A DENIED/NOT_FOUND item must **not inflate `grounding` to a free 1.0** — grounding/citation average over answered items only; refusal is scored separately. → Task 5.
4. `aggregate` on an **empty or all-refused** subset returns a defined value (no `ZeroDivisionError`/NaN) with deterministic ordering. → Task 5.
5. The citation grammar is **single-sourced**: a change to the pipeline's citation rule can't silently desync the metric. → Task 2.

---

### Task 1: Eval records (`EvalItem`, `EvalResult`)

**Files:**
- Create: `src/secure_ai_research/evaluation/records.py`
- Test: `tests/test_eval_records.py`

**Interfaces:**
- Consumes: `Outcome` from `secure_ai_research.research_service`.
- Produces (both `pydantic.BaseModel`, `model_config = ConfigDict(frozen=True)`):
  - `EvalItem`: `id: str`, `kind: Literal["cve", "attack", "search", "authz", "injection"]`, `query: str`, `role: str`, `expected_outcome: Outcome`, `gold_document_ids: frozenset[str]`, `must_not_appear: frozenset[str] = frozenset()`, `note: str = ""`.
  - `EvalResult`: `item: EvalItem`, `outcome: Outcome`, `cited_ids: tuple[str, ...]`, `retrieved_ids: tuple[str, ...]`, `answer: str`.

- [ ] **Step 1: Write the failing test**

```python
def test_eval_item_defaults_and_frozen():
    item = EvalItem(id="i1", kind="cve", query="CVE-2021-44228",
                    role="research_analyst", expected_outcome=Outcome.OK,
                    gold_document_ids=frozenset({"CVE-2021-44228"}))
    assert item.must_not_appear == frozenset() and item.note == ""
    assert item.expected_outcome is Outcome.OK
    with pytest.raises(ValidationError):
        item.role = "senior_analyst"  # frozen

def test_eval_result_holds_pipeline_shape():
    item = EvalItem(id="i1", kind="search", query="log4j", role="research_analyst",
                    expected_outcome=Outcome.OK, gold_document_ids=frozenset())
    res = EvalResult(item=item, outcome=Outcome.OK, cited_ids=("KEV-CVE-2021-44228",),
                     retrieved_ids=("KEV-CVE-2021-44228",), answer="…")
    assert res.item.kind == "search" and res.outcome is Outcome.OK
```

- [ ] **Step 2: Run `.venv/bin/pytest tests/test_eval_records.py -q` — Expected: FAIL (cannot import `EvalItem`).**
- [ ] **Step 3: Implement `records.py`** with the two frozen models and the imports (`Literal` from `typing`, `BaseModel`/`ConfigDict`/`ValidationError` from `pydantic`, `Outcome` from `research_service`).
- [ ] **Step 4: Run `.venv/bin/pytest tests/test_eval_records.py -q` — Expected: PASS.**
- [ ] **Step 5: Commit** (`git add src/secure_ai_research/evaluation/records.py tests/test_eval_records.py`).

---

### Task 2: Single-source the citation grammar (`citation_ids`)

**Files:**
- Modify: `src/secure_ai_research/reporting/report.py` (add helper; refactor `build_report` line that calls `_CITATION.findall`)
- Test: `tests/test_report.py`

**Interfaces:**
- Produces: `citation_ids(text: str) -> list[str]` — the CVE/ATT&CK citation ids in `text`, using the existing `_CITATION` grammar. `build_report` calls it instead of `_CITATION.findall(line)` (behavior unchanged).

- [ ] **Step 1: Write the failing test** (in `tests/test_report.py`)

```python
def test_citation_ids_matches_grammar():
    assert citation_ids("rce [CVE-2021-44228] and [T1059.001] not buf[256] nor [CWE-79]") \
        == ["CVE-2021-44228", "T1059.001"]
    assert citation_ids("no citation here") == []
```

- [ ] **Step 2: Run `.venv/bin/pytest tests/test_report.py::test_citation_ids_matches_grammar -q` — Expected: FAIL (`citation_ids` undefined).**
- [ ] **Step 3: Implement `citation_ids`** as `return _CITATION.findall(text)` and change `build_report`'s `cited = _CITATION.findall(line)` to `cited = citation_ids(line)`.
- [ ] **Step 4: Run `.venv/bin/pytest tests/test_report.py -q` — Expected: PASS (new test + all existing `build_report` tests; behavior unchanged).**
- [ ] **Step 5: Commit.**

---

### Task 3: `grounding` + retire the `metrics.score` stub

**Files:**
- Modify: `src/secure_ai_research/evaluation/metrics.py` (replace the `score` stub)
- Modify: `tests/test_stubs.py` (remove the retired function-stub scaffolding)
- Test: `tests/test_eval_metrics.py`

**Interfaces:**
- Consumes: `EvalResult` (Task 1), `citation_ids` (Task 2).
- Produces: `grounding(result: EvalResult) -> float`.

**Definition (the one algorithm the signature doesn't fix):** split `result.answer` into lines; ignore the title line (`startswith("# Research report:")`), the trailing `Sources:` line, blank lines, and `No cited findings.`. For each remaining **body line**, `ids = citation_ids(line)`; the line is *grounded* iff `ids` is non-empty **and** every id ∈ `result.retrieved_ids`. `grounding = grounded_lines / body_lines`, or `1.0` when there are zero body lines (nothing false was claimed).

- [ ] **Step 1: Write the failing tests** (`tests/test_eval_metrics.py`)

```python
def _ok(answer, retrieved, kind="cve"):
    item = EvalItem(id="x", kind=kind, query="q", role="research_analyst",
                    expected_outcome=Outcome.OK, gold_document_ids=frozenset(retrieved))
    return EvalResult(item=item, outcome=Outcome.OK, cited_ids=tuple(retrieved),
                      retrieved_ids=tuple(retrieved), answer=answer)

def test_grounding_all_cited_is_one():
    ans = "# Research report: q\n\nrce [CVE-2021-44228]\n\nSources: CVE-2021-44228"
    assert grounding(_ok(ans, ["CVE-2021-44228"])) == 1.0

def test_grounding_uncited_line_scores_zero():  # Review Focus 1 (load-bearing)
    ans = ("# Research report: q\n\nrce [CVE-2021-44228]\nbackdoor with no citation\n\n"
           "Sources: CVE-2021-44228")
    assert grounding(_ok(ans, ["CVE-2021-44228"])) == 0.5

def test_grounding_cited_to_unretrieved_scores_zero():
    ans = "# Research report: q\n\nclaim [CVE-2099-0001]\n\nSources: CVE-2021-44228"
    assert grounding(_ok(ans, ["CVE-2021-44228"])) == 0.0
```

- [ ] **Step 2: Run `.venv/bin/pytest tests/test_eval_metrics.py -q` — Expected: FAIL (`grounding` undefined).**
- [ ] **Step 3: Implement `grounding` in `metrics.py`** per the Definition; **remove the `score` stub**. Update the module docstring to the honest-scope note (measures the pipeline, not a model; model-behavior metrics are deferred behind the Phase-4 seam).
- [ ] **Step 4: Retire the stub scaffolding in `tests/test_stubs.py`:** remove `from …evaluation import metrics`, the `STUB_CALLS`/`IDS` definitions, and the two tests that iterate them (`test_all_stubs_raise_notimplemented`, `test_all_stubs_have_docstrings`); **keep** `test_adapter_stubs_raise_on_construction` (OllamaEmbedder/PgVectorStore are still Phase-5 stubs). This mirrors the sigma/search slices retiring an implemented stub + its `test_stubs` entry.
- [ ] **Step 5: Run `.venv/bin/pytest tests/test_eval_metrics.py tests/test_stubs.py -q` — Expected: PASS (grounding green; test_stubs collects with only the adapter test).**
- [ ] **Step 6: Commit.**

---

### Task 4: `citation_accuracy` + `refusal_correct`

**Files:**
- Modify: `src/secure_ai_research/evaluation/metrics.py`
- Test: `tests/test_eval_metrics.py`

**Interfaces:**
- Consumes: `EvalResult` (Task 1).
- Produces: `citation_accuracy(result: EvalResult) -> float`, `refusal_correct(result: EvalResult) -> bool`.

**Definitions:** `citation_accuracy` — `cited = set(result.cited_ids)`, `gold = result.item.gold_document_ids`; if `cited` is empty return `1.0` when `gold` is empty else `0.0`; otherwise `len(cited & gold) / len(cited)`. `refusal_correct` — `result.outcome == result.item.expected_outcome`.

- [ ] **Step 1: Write the failing tests**

```python
def test_citation_accuracy_all_gold_is_one():
    r = _ok("…", ["CVE-2021-44228"]); assert citation_accuracy(r) == 1.0

def test_citation_accuracy_non_gold_citation_lowers_it():  # Review Focus 2
    item = EvalItem(id="x", kind="search", query="q", role="research_analyst",
                    expected_outcome=Outcome.OK, gold_document_ids=frozenset({"KEV-CVE-2021-44228"}))
    r = EvalResult(item=item, outcome=Outcome.OK,
                   cited_ids=("KEV-CVE-2021-44228", "SIGMA-wrong"),
                   retrieved_ids=("KEV-CVE-2021-44228", "SIGMA-wrong"), answer="…")
    assert citation_accuracy(r) == 0.5

def test_citation_accuracy_empty_cited_against_gold_is_zero():
    item = EvalItem(id="x", kind="cve", query="q", role="research_analyst",
                    expected_outcome=Outcome.OK, gold_document_ids=frozenset({"CVE-2021-44228"}))
    r = EvalResult(item=item, outcome=Outcome.OK, cited_ids=(), retrieved_ids=(), answer="…")
    assert citation_accuracy(r) == 0.0

def test_refusal_correct_matches_expected_outcome():
    item = EvalItem(id="x", kind="cve", query="q", role="intern",
                    expected_outcome=Outcome.DENIED, gold_document_ids=frozenset())
    denied = EvalResult(item=item, outcome=Outcome.DENIED, cited_ids=(), retrieved_ids=(), answer="")
    served = EvalResult(item=item, outcome=Outcome.OK, cited_ids=(), retrieved_ids=(), answer="…")
    assert refusal_correct(denied) is True and refusal_correct(served) is False
```

- [ ] **Step 2: Run `.venv/bin/pytest tests/test_eval_metrics.py -q` — Expected: FAIL (`citation_accuracy`/`refusal_correct` undefined).**
- [ ] **Step 3: Implement both** in `metrics.py` per the Definitions.
- [ ] **Step 4: Run `.venv/bin/pytest tests/test_eval_metrics.py -q` — Expected: PASS.**
- [ ] **Step 5: Commit.**

---

### Task 5: `aggregate`

**Files:**
- Modify: `src/secure_ai_research/evaluation/metrics.py`
- Test: `tests/test_eval_metrics.py`

**Interfaces:**
- Consumes: `grounding`, `citation_accuracy`, `refusal_correct`, `EvalResult`.
- Produces: `aggregate(results: list[EvalResult]) -> dict[str, float]` with keys `grounding`, `citation_accuracy`, `refusal_accuracy`, `n_total`, `n_answered`.

**Definition:** `answered = [r for r in results if r.outcome == Outcome.OK]`. `grounding` = mean of `grounding(r)` over `answered` with `r.item.kind in {"cve", "attack"}`; `citation_accuracy` = mean of `citation_accuracy(r)` over `answered` with `r.item.kind in {"cve", "attack", "search"}`; each empty subset → `1.0` (vacuous, no failing item). `refusal_accuracy` = mean of `refusal_correct(r)` over **all** `results`; empty → `1.0`. `n_total = float(len(results))`, `n_answered = float(len(answered))`. Iterate in list order (deterministic).

- [ ] **Step 1: Write the failing tests**

```python
def test_aggregate_denied_item_does_not_inflate_grounding():  # Review Focus 3
    ok = _ok("# Research report: q\n\nrce [CVE-2021-44228]\n\nSources: CVE-2021-44228",
             ["CVE-2021-44228"])
    denied_item = EvalItem(id="d", kind="cve", query="q", role="intern",
                           expected_outcome=Outcome.DENIED, gold_document_ids=frozenset())
    denied = EvalResult(item=denied_item, outcome=Outcome.DENIED, cited_ids=(),
                        retrieved_ids=(), answer="")
    agg = aggregate([ok, denied])
    assert agg["grounding"] == 1.0 and agg["n_answered"] == 1.0 and agg["n_total"] == 2.0
    assert agg["refusal_accuracy"] == 1.0  # ok→OK expected OK, denied→DENIED expected DENIED

def test_aggregate_empty_is_defined_not_crash():  # Review Focus 4
    agg = aggregate([])
    assert agg == {"grounding": 1.0, "citation_accuracy": 1.0, "refusal_accuracy": 1.0,
                   "n_total": 0.0, "n_answered": 0.0}
```

- [ ] **Step 2: Run `.venv/bin/pytest tests/test_eval_metrics.py -q` — Expected: FAIL (`aggregate` undefined).**
- [ ] **Step 3: Implement `aggregate`** per the Definition (guard every mean against an empty subset).
- [ ] **Step 4: Run the whole hermetic suite `.venv/bin/pytest -q -m "not integration"` — Expected: PASS (all prior + new; `test_stubs` still green).**
- [ ] **Step 5: Run linters `.venv/bin/ruff check . && .venv/bin/black --check . && .venv/bin/mypy` — Expected: all clean.**
- [ ] **Step 6: Commit.**
