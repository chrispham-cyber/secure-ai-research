# End-to-end CVE-correlation demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A runnable, offline, stdlib-only demo that drives the real assembled Phase-2 corpus and shows a CVE pivot correlating across CISA KEV + SigmaHQ and an ATT&CK-technique pivot correlating across MITRE ATT&CK + SigmaHQ, with an audit record per pivot — closing ROADMAP Week 8's correlation-demo line.

**Architecture:** A new `demo` package (`src/secure_ai_research/demo/correlation.py`) that builds the four-fixture corpus offline (same loaders as `deps`, minus live-fetch), runs each pivot through the real `ResearchService.search(...)` authorize-before-retrieve path, keeps the retrieved documents that explicitly reference the pivot identifier (the correlation criterion — the in-posture bag-of-words embedder ranks the genuine matches top but has a noisy tail), groups them by source, and renders a report. A hermetic test pins the correlation and the audit trail. No change to any existing module.

**Tech Stack:** Python 3.12, stdlib only at runtime, FastAPI/pydantic already present; no new dependency.

**Spec:** `docs/superpowers/specs/2026-11-19-phase2-correlation-demo-design.md`

## Global Constraints

- stdlib-only at runtime, no new dependency. Deterministic, offline, hermetic (no `@pytest.mark.integration`).
- PUBLIC/synthetic only; uses the already-committed fixtures.
- **Do NOT modify** `ResearchService`, the loaders, `authz`, `deps`, the id-routes, `search`, or `build_report`. This slice only *adds* a `demo` package, a test, a doc, and ROADMAP edits.
- The demo calls the real `service.search(...)` over the real authz gate — it must not reimplement retrieval, ranking, or authorization.
- `ruff`/`black`/`mypy` clean; line length 100. Every commit ends with the attribution footer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU`.

## Review Focus

1. **Real pipeline, not faked** — correlation comes from `service.search(...)` over the authz gate and the assembled corpus; citations are not hand-built — Task 1 `test_correlate_*` drive a real corpus.
2. **Determinism / hermeticity** — no network, no wall-clock dependence; report byte-stable; test has no `integration` marker — Task 1 (fixtures only; `SAIR_ALLOW_LIVE_FETCH` never set).
3. **Correlation is genuine, not loose** — the CVE pivot yields exactly `{CISA KEV, SigmaHQ}` (no NVD-2099 noise), the technique pivot yields ATT&CK + SigmaHQ — Task 1 `test_correlate_cve_is_exactly_kev_and_sigma`.
4. **Zero blast radius** — only a new `demo` package, a test, a doc, ROADMAP edits in the diff — final review (changed-files set).
5. **Honest ROADMAP** — only delivered in-posture lines ticked; infra-gated lines stay unchecked + annotated — Task 2.

---

### Task 1: `demo` package + hermetic correlation test

**Files:**
- Create: `src/secure_ai_research/demo/__init__.py` (package marker; one-line docstring)
- Create: `src/secure_ai_research/demo/correlation.py`
- Test: `tests/test_correlation_demo.py`

**Interfaces:**
- Consumes (existing): `nvd.load`, `attack.load`, `kev.load`, `sigma.load`; `ResearchService(embedder, store, authorize, audit_path)` with `.index(list[IngestedDocument])` and `.search(query, *, role, limit) -> ResearchResult`; `ResearchResult.citations: list[Citation]`; `Citation.document_id`, `Citation.passage`; `HashingEmbedder`, `InMemoryVectorStore`, `authorize`; `read_records(path)` (for the test).
- Produces: `_source_of(document_id: str) -> str`; `correlate(service: ResearchService, pivot: str) -> dict[str, list[str]]`; `build_offline_corpus(audit_path: Path) -> ResearchService`; `build_correlation_report(service: ResearchService, pivots: list[tuple[str, str]]) -> str`; `_PIVOTS: list[tuple[str, str]]`; `_SEARCH_LIMIT: int`; `main() -> None`.

- [ ] **Step 1: Write the failing tests** in `tests/test_correlation_demo.py`

```python
from pathlib import Path

from secure_ai_research.audit.record import read_records
from secure_ai_research.demo import correlation
from secure_ai_research.demo.correlation import (
    _PIVOTS,
    _source_of,
    build_correlation_report,
    build_offline_corpus,
    correlate,
)

_KEV = "CISA KEV (known-exploited)"
_SIGMA = "SigmaHQ (detection)"
_ATTACK = "MITRE ATT&CK (technique)"


def _corpus(tmp_path) -> tuple:
    audit = tmp_path / "audit.jsonl"
    return build_offline_corpus(audit), audit


def test_source_of_maps_each_namespace():
    assert _source_of("KEV-CVE-2021-44228") == _KEV
    assert _source_of("SIGMA-abc") == _SIGMA
    assert _source_of("T1059") == _ATTACK
    assert _source_of("T1059.001") == _ATTACK
    assert _source_of("CVE-2099-0001") == "NVD (vulnerability)"
    assert _source_of("weird-id") == "other"


def test_correlate_cve_is_exactly_kev_and_sigma(tmp_path):
    svc, _ = _corpus(tmp_path)
    result = correlate(svc, "CVE-2021-44228")
    assert result == {
        _KEV: ["KEV-CVE-2021-44228"],
        _SIGMA: ["SIGMA-3eb91f0a-0060-424a-a676-59f5fdd75610"],
    }


def test_correlate_technique_spans_attack_and_sigma(tmp_path):
    svc, _ = _corpus(tmp_path)
    result = correlate(svc, "T1059")
    assert _ATTACK in result and "T1059" in result[_ATTACK]
    assert _SIGMA in result and any(i.startswith("SIGMA-") for i in result[_SIGMA])


def test_report_renders_both_pivots(tmp_path):
    svc, _ = _corpus(tmp_path)
    report = build_correlation_report(svc, _PIVOTS)
    assert "CVE-2021-44228" in report and "KEV-CVE-2021-44228" in report
    assert "T1059" in report and "SIGMA-" in report
    assert _KEV in report and _ATTACK in report and _SIGMA in report


def test_one_audit_record_per_pivot_with_correlated_sources(tmp_path):
    svc, audit = _corpus(tmp_path)
    build_correlation_report(svc, _PIVOTS)  # two searches
    records = read_records(audit)
    assert len(records) == 2
    cve_rec = next(r for r in records if "KEV-CVE-2021-44228" in r.retrieved_doc_ids)
    assert {"CISA KEV", "Sigma"} <= set(cve_rec.data_source_ids)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_correlation_demo.py -q`
Expected: FAIL at import — `secure_ai_research.demo` does not exist yet (ModuleNotFoundError).

- [ ] **Step 3: Create the package marker** `src/secure_ai_research/demo/__init__.py`

A module docstring only, e.g. `"""Runnable, offline demonstrations of the Phase-2 retrieval pipeline."""`.

- [ ] **Step 4: Implement** `src/secure_ai_research/demo/correlation.py`

Module constants after imports: `_SEARCH_LIMIT = 10`; `_PIVOTS = [("Log4Shell", "CVE-2021-44228"), ("Command and Scripting Interpreter", "T1059")]`; a `_TECHNIQUE = re.compile(r"T\d")`.

```python
def _source_of(document_id: str) -> str:
    if document_id.startswith("KEV-"):
        return "CISA KEV (known-exploited)"
    if document_id.startswith("SIGMA-"):
        return "SigmaHQ (detection)"
    if document_id.startswith("CVE-"):
        return "NVD (vulnerability)"
    if _TECHNIQUE.match(document_id):
        return "MITRE ATT&CK (technique)"
    return "other"


def build_offline_corpus(audit_path: Path) -> ResearchService:
    service = ResearchService(HashingEmbedder(), InMemoryVectorStore(), authorize, audit_path)
    pkg = files("secure_ai_research.ingestion")
    for name, loader in (
        ("nvd_sample.json", nvd.load),
        ("attack_sample.json", attack.load),
        ("kev_sample.json", kev.load),
        ("sigma_sample.json", sigma.load),
    ):
        service.index(loader(pkg.joinpath("samples", name).read_bytes()))
    return service


def correlate(service: ResearchService, pivot: str) -> dict[str, list[str]]:
    res = service.search(pivot, role="research_analyst", limit=_SEARCH_LIMIT)
    grouped: dict[str, list[str]] = {}
    for c in res.citations:
        if pivot in c.passage:  # the document genuinely references the pivot id
            grouped.setdefault(_source_of(c.document_id), []).append(c.document_id)
    return dict(sorted(grouped.items()))


def build_correlation_report(service: ResearchService, pivots: list[tuple[str, str]]) -> str:
    lines: list[str] = ["# Phase-2 cross-source correlation", ""]
    for label, pivot in pivots:
        grouped = correlate(service, pivot)
        lines.append(f"## {label} — {pivot}")
        if grouped:
            for source, ids in grouped.items():
                lines.append(f"  - {source}: {', '.join(ids)}")
        else:
            lines.append("  (no correlated documents)")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        service = build_offline_corpus(Path(tmp) / "audit.jsonl")
        print(build_correlation_report(service, _PIVOTS))


if __name__ == "__main__":
    main()
```

Imports: `from __future__ import annotations`; `import re`, `import tempfile`; `from pathlib import Path`; `from importlib.resources import files`; `from secure_ai_research.ingestion import attack, kev, nvd, sigma`; `from secure_ai_research.research_service import ResearchService`; `from secure_ai_research.retrieval.authz import authorize`; `from secure_ai_research.retrieval.embeddings import HashingEmbedder`; `from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_correlation_demo.py -q`
Expected: PASS (all 5).

- [ ] **Step 6: Verify the runnable entry works**

Run: `.venv/bin/python -m secure_ai_research.demo.correlation`
Expected: prints the report; the Log4Shell block shows `CISA KEV (known-exploited): KEV-CVE-2021-44228` and `SigmaHQ (detection): SIGMA-3eb91f0a-…`; the T1059 block shows `MITRE ATT&CK (technique): T1059` and a `SigmaHQ (detection): SIGMA-…`. (Read the output; it is the demo artifact.)

- [ ] **Step 7: Lint + commit**

Run: `.venv/bin/ruff check . && .venv/bin/black --check . && .venv/bin/mypy`
Expected: clean.
```bash
git add src/secure_ai_research/demo/__init__.py src/secure_ai_research/demo/correlation.py tests/test_correlation_demo.py
git commit   # feat(demo): end-to-end cross-source correlation demo  (+ footer)
```

---

### Task 2: Walkthrough doc + ROADMAP

**Files:**
- Create: `docs/phase2-correlation-demo.md`
- Modify: `ROADMAP.md` (tick delivered in-posture Phase-2 lines; annotate infra-gated lines as deferred)

**Interfaces:** none (documentation only; consumes Task 1's `python -m` entry in its instructions).

- [ ] **Step 1: Write `docs/phase2-correlation-demo.md`**

Cover: what the demo shows; the two pivots and which sources each correlates (CVE-2021-44228 → CISA KEV + SigmaHQ; T1059 → MITRE ATT&CK + SigmaHQ); how to run it (`python -m secure_ai_research.demo.correlation`) and the test (`pytest tests/test_correlation_demo.py`); and the in-posture caveats — retrieval-only / no LLM synthesis; the bag-of-words `HashingEmbedder` is a placeholder (real embeddings = deferred Ollama) so the demo keeps the documents that explicitly reference the pivot; NVD would also appear for the CVE pivot via opt-in `SAIR_ALLOW_LIVE_FETCH` (default off); pgvector/MinIO/Ollama/local-generation deferred.

- [ ] **Step 2: Update `ROADMAP.md`**

In the Phase 2 block, change `- [ ]` to `- [x]` only for the genuinely-delivered in-posture lines: Week 5 NVD/CISA KEV loaders; Week 6 ATT&CK + Sigma (ingestion); Week 7 authorize-before-retrieve + nearest-neighbor within scope; Week 8 cited report rendering + wire `/research/*` live + per-analysis audit record + end-to-end CVE-correlation demo. Leave the infra-gated lines **unchecked** and append a short parenthetical to each — Week 5 MinIO/pgvector, Week 6 Ollama embeddings + pgvector upsert, Week 7 local generation model — e.g. `(deferred — out of the in-posture offline/stdlib envelope; Protocol seams in place)`. Do not alter other phases.

- [ ] **Step 3: Verify nothing else changed + commit**

Run: `git diff --stat` — only `docs/phase2-correlation-demo.md` (new) and `ROADMAP.md` (modified).
Run: `.venv/bin/pytest -q` — full suite still green (doc/ROADMAP edits touch no code).
```bash
git add docs/phase2-correlation-demo.md ROADMAP.md
git commit   # docs(phase2): correlation-demo walkthrough + tick delivered ROADMAP lines  (+ footer)
```

---

## Final checks (before review)

- [ ] `.venv/bin/pytest -q` — full suite green (hermetic).
- [ ] `.venv/bin/ruff check . && .venv/bin/black --check . && .venv/bin/mypy` — clean.
- [ ] `.venv/bin/python -m secure_ai_research.demo.correlation` — prints the clean two-pivot correlation.
- [ ] `git diff --stat main..HEAD` — only the `demo` package, the test, the doc, the design, the plan, and ROADMAP.
