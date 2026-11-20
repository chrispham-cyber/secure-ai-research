# Portfolio Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the repo's front-door docs tell the truth about the finished 6-phase platform, and surface the assurance evidence that already exists — with no logic changes.

**Architecture:** Two tasks. Task 1 is test-gated: a new hermetic test pins the README + the now-real module docstrings to reality, then the README is rewritten and the stale docstrings corrected to pass it. Task 2 is review-/grep-gated: CHANGELOG, ROADMAP intro, and the pyproject description are brought current (doc/config — TDD exception per the spec), verified by the suite staying green.

**Tech Stack:** Markdown, Python (pytest), TOML. Hermetic stdlib only.

**Spec:** docs/superpowers/specs/2026-11-20-portfolio-polish-design.md

## Global Constraints

- Repo stays **PRIVATE** (`github.com/chrispham-cyber/secure-ai-research`); **no public step**, no public-exposure secrets sweep.
- **No logic changes anywhere.** `src/secure_ai_research/retrieval/authz.py` and `research_service.py` are **not touched at all** (not even docstrings). All other src edits are docstring/comment **text only**.
- The one honest fail-loud stub, `OllamaEmbedder`, stays as-is; `tests/test_stubs.py` stays green. The README/docstrings name it honestly (term: "fail-loud stub", never "documented stub").
- `tests/test_compliance_docs.py` and `tests/test_control_evidence.py` stay green; the `documentation/` files they read are **not** modified by this slice.
- Every backticked path / markdown link / pytest node added to docs must resolve on disk.
- Test command: `./.venv/bin/pytest -q -m "not integration"` (expect 467 passed after each task).
- Version stays `0.1.0`.

## Review Focus

- **A relative link added to the README points at a nonexistent file** — a broken link in the showcase README; a reader clicks and 404s. → covered by `test_readme_relative_links_resolve` (Task 1).
- **The README overstates a capability** (claims something real that is actually the `OllamaEmbedder` stub, or claims live-model use the default path doesn't do) — the honesty anti-goal. → partially pinned by the docstring + `test_stubs.py` guards; otherwise the reviewer verifies each capability claim against the code, especially the embeddings/Ollama nuance.
- **A docstring edit silently changes behavior** (edits a non-docstring line, or breaks a module that is imported) → the full suite imports every touched module; a broken edit fails collection. Reviewer confirms each diff hunk is inside a docstring.
- **The CI-badge URL names the wrong repo/owner or workflow file**, so it renders broken even for an authenticated viewer → `test_readme_shows_ci_and_coverage` checks the workflow path substring; the reviewer confirms owner `chrispham-cyber` and file `ci.yml` exactly.
- **A compliance-doc linter breaks** because a cited path was moved or a `documentation/` file was touched → both tasks run the full suite; `test_control_evidence.py` / `test_compliance_docs.py` failing would surface it.

---

### Task 1: Currency test + README rewrite + docstring de-stale

**Files:**
- Create: `tests/test_readme_currency.py`
- Modify: `README.md` (rewrite)
- Modify (docstring text only): `src/secure_ai_research/reporting/__init__.py`, `src/secure_ai_research/ingestion/__init__.py`, `src/secure_ai_research/agents/__init__.py`, `src/secure_ai_research/ai_security/__init__.py`, `src/secure_ai_research/retrieval/__init__.py`, `src/secure_ai_research/evaluation/__init__.py`, `src/secure_ai_research/api/__init__.py`, `src/secure_ai_research/api/main.py`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `tests/test_readme_currency.py` (the doc-currency guard). Task 2 does not depend on it.

- [ ] **Step 1: Write the failing test** at `tests/test_readme_currency.py`. Use the repo root via `Path(__file__).resolve().parents[1]`. Collapse README whitespace once (`_NORM = " ".join(README.split())`) for phrase checks so line-wraps don't hide a phrase.

```python
from pathlib import Path
import re

_REPO = Path(__file__).resolve().parents[1]
_README = (_REPO / "README.md").read_text(encoding="utf-8")
_NORM = " ".join(_README.split())
_NOW_REAL = ["reporting", "ingestion", "agents", "ai_security", "retrieval", "evaluation"]

def test_readme_status_is_current():
    # the stale Phase-1 status line is gone (em-dash U+2014, as in the file)
    assert "Phase 1 — foundation scaffold" not in _NORM

def test_research_endpoints_not_described_as_501():
    # /research/* are implemented; the 501 claim (line-wrapped in the old README) is gone
    assert "501 Not Implemented" not in _NORM

def test_readme_shows_ci_and_coverage():
    assert "actions/workflows/ci.yml/badge.svg" in _README
    assert "467" in _README  # unit-test count

def test_readme_surfaces_compliance_evidence():
    assert "documentation/assessment-evidence/control-evidence-matrix.md" in _README

def test_now_real_module_docstrings_are_not_stale():
    # bans the substring "documented stub" (covers "documented stub(s)[ and test designs]");
    # the honest OllamaEmbedder note in retrieval uses "fail-loud stub", which does not match.
    for mod in _NOW_REAL:
        text = (_REPO / "src/secure_ai_research" / mod / "__init__.py").read_text(encoding="utf-8").lower()
        assert "documented stub" not in text, f"{mod}/__init__.py still calls itself a documented stub"

def test_readme_relative_links_resolve():
    # every relative markdown link target resolves on disk (external http(s) and pure #anchors skipped)
    targets = re.findall(r"\]\(([^)]+)\)", _README)
    missing = []
    for t in targets:
        if t.startswith("http") or t.startswith("#"):
            continue
        path = t.split("#", 1)[0]
        if path and not (_REPO / path).exists():
            missing.append(t)
    assert missing == [], f"README has broken relative links: {missing}"
```

- [ ] **Step 2: Run the test; verify the content/docstring assertions fail**

Run: `./.venv/bin/pytest tests/test_readme_currency.py -q`
Expected: FAIL — `test_readme_status_is_current`, `test_research_endpoints_not_described_as_501`, `test_readme_shows_ci_and_coverage`, `test_readme_surfaces_compliance_evidence`, and `test_now_real_module_docstrings_are_not_stale` all fail against the current stale docs.

- [ ] **Step 3: Prove the link guard works** — temporarily append `[bogus](does/not/exist.md)` to `README.md`, run `./.venv/bin/pytest tests/test_readme_currency.py::test_readme_relative_links_resolve -q` (Expected: FAIL listing `does/not/exist.md`), then remove that line. (The guard passes on the real README; this shows it can catch a bad link.)

- [ ] **Step 4: Rewrite `README.md`** so every assertion above passes and the page leads with the finished security story. Required content (prose is the implementer's, within these):
  - **Status** reflecting the real state: platform complete through Phase 5; deterministic/offline/stdlib **default** path fully implemented and tested; real infra behind opt-in `SAIR_*` seams; the **one** remaining fail-loud stub is `OllamaEmbedder` (local embedding via Ollama), the default `HashingEmbedder` being real.
  - A **CI badge** at the top: `![CI](https://github.com/chrispham-cyber/secure-ai-research/actions/workflows/ci.yml/badge.svg)` (note in prose or a comment that it renders for authenticated viewers of the private repo). One line stating **467 unit + 20 integration** tests.
  - "What's real vs stubbed" corrected to reality: ingestion loaders, chunking/embeddings(`HashingEmbedder`)/vectorstore/authz, agents, evaluation, reporting, and `/research/*` are **real**; `OllamaEmbedder` is the lone fail-loud stub.
  - Quickstart: replace the "`/research/*` return **501 Not Implemented**" note with the **real routes** — `GET /research/cve/{cve_id}`, `GET /research/attack/{technique_id}`, `POST /research/search`, `POST /research/ask`.
  - Repo-map: drop stale `(stubs)` / `(real)` annotations that no longer hold.
  - A **Security & Compliance** section linking (all must resolve): `architecture/threat-model.md`, `documentation/assessment-evidence/control-evidence-matrix.md` (name the NIST controls **AC-3, AU-10, IA-2, IA-5, SC-8, SC-28**), `documentation/risk-assessment/risk-register.md`, `documentation/system-security-plan/system-security-plan.md`, `documentation/sbom/sbom-guide.md`, and the four opt-in seams `SAIR_VECTOR_STORE=pgvector` / `SAIR_OBJECT_STORE=minio` / `SAIR_AUTH=oidc` / `SAIR_CIPHER=fernet`.

- [ ] **Step 5: Correct the stale docstrings** (text only). For each module, read its real code first, then replace the "stub/501" line with a one-line accurate description of what the module does now. Describe only what is genuinely implemented in that package:
  - `reporting/__init__.py` — cited-report rendering (drop-uncited-claims + citation faithfulness).
  - `ingestion/__init__.py` — document schema + NVD/KEV/ATT&CK/Sigma loaders.
  - `agents/__init__.py` — agent toolset with authority checks enforced outside the LLM.
  - `ai_security/__init__.py` — model-integrity verifier (`model_integrity.verify_model`, real SHA-256); note injection-robustness/agent-authority controls live in `evaluation/`/`agents/`. Do **not** reintroduce "documented stub(s)".
  - `retrieval/__init__.py` — chunking, `HashingEmbedder` (real default), vectorstore (in-memory default + opt-in pgvector), authz; the **one** remaining fail-loud stub is `OllamaEmbedder`.
  - `evaluation/__init__.py` — evaluation metrics + synthetic-benchmark harness.
  - `api/__init__.py` — real `/research/*` routes (drop "return 501 until the retrieval pipeline exists").
  - `api/main.py` — module docstring: list the real `/research/*` routes instead of "501 Not Implemented".

- [ ] **Step 6: Run the currency test; verify it passes**

Run: `./.venv/bin/pytest tests/test_readme_currency.py -q`
Expected: PASS (6 passed).

- [ ] **Step 7: Run the full hermetic suite**

Run: `./.venv/bin/pytest -q -m "not integration"`
Expected: PASS — 467 passed (incl. `test_stubs.py`, `test_compliance_docs.py`, `test_control_evidence.py`); the new file adds 6, so the reported count is 467 + 6 = **473 passed**.

- [ ] **Step 8: Commit**

```bash
git add tests/test_readme_currency.py README.md src/secure_ai_research/reporting/__init__.py src/secure_ai_research/ingestion/__init__.py src/secure_ai_research/agents/__init__.py src/secure_ai_research/ai_security/__init__.py src/secure_ai_research/retrieval/__init__.py src/secure_ai_research/evaluation/__init__.py src/secure_ai_research/api/__init__.py src/secure_ai_research/api/main.py
git commit -m "docs: make README + module docstrings reflect the finished platform"
```

---

### Task 2: CHANGELOG + ROADMAP intro + pyproject description

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `ROADMAP.md` (intro line ~10)
- Modify: `pyproject.toml` (`description`, line 8)

**Interfaces:**
- Consumes: nothing. Independent of Task 1.
- Produces: nothing other tasks consume.

- [ ] **Step 1: Add a CHANGELOG entry** above `## [0.1.0]` summarizing the Phase 2–5 arc: evidence-grounded RAG + `/research/*` endpoints (CVE/ATT&CK/search/ask); AI-specific security (model-integrity verifier, prompt-injection robustness harness, agent authority checks outside the LLM); evaluation & red-teaming (metrics, synthetic benchmark); deploy & assurance (OIDC/JWT identity, tamper-evident signed audit chain, at-rest cipher seam, reproducible CycloneDX SBOM + integrity manifest, STRIDE threat model, NIST control→evidence matrix, risk register, SSP). Head it `## [Unreleased]`. Keep the Keep-a-Changelog style; version stays `0.1.0`.

- [ ] **Step 2: Update the `ROADMAP.md` intro line** (~line 10: "Checkboxes track progress; Phase 1 is largely complete in this starter repo.") to state that Phases 1–5 are built and the deterministic/offline default path is complete; keep the sentence accurate to the checkboxes below it.

- [ ] **Step 3: Update `pyproject.toml` `description`** (line 8) from "Starter scaffold for a secure AI-assisted cybersecurity research platform (public/synthetic data only)." to finished-state wording, e.g. "A secure-by-design, evidence-grounded AI research platform for cybersecurity (public/synthetic data only)." Metadata only; do not change `version`.

- [ ] **Step 4: Verify the stale phrases are gone**

Run: `grep -n "Phase 1 is largely complete" ROADMAP.md; grep -n "Starter scaffold" pyproject.toml; grep -c "Unreleased" CHANGELOG.md`
Expected: the first two greps print **nothing** (exit 1); the third prints `1`.

- [ ] **Step 5: Run the full hermetic suite (no regression)**

Run: `./.venv/bin/pytest -q -m "not integration"`
Expected: PASS — **473 passed** (unchanged from Task 1; these are doc/config edits).

- [ ] **Step 6: Commit**

```bash
git add CHANGELOG.md ROADMAP.md pyproject.toml
git commit -m "docs: changelog phase 2-5 arc; current roadmap intro + package description"
```

---

## Self-Review

**1. Spec coverage:** README rewrite (status/badge/counts/real-vs-stub/routes/repo-map/Security&Compliance) → Task 1 Step 4. Docstrings (8 files) → Task 1 Step 5. CHANGELOG → Task 2 Step 1. ROADMAP intro → Task 2 Step 2. pyproject description → Task 2 Step 3. Honest `OllamaEmbedder` caveat → enforced by the "documented stub" ban + `test_stubs.py` untouched. No-logic-change / authz untouched → Global Constraints + Review Focus. All spec sections covered.

**2. Step scan:** Each step is one action with a checkable result; the only code block is the test (its assertions are the spec's exact values) and the link-guard algorithm (a regex the signature doesn't determine). README/docstring/changelog prose is left to the implementer, bounded by the required-content lists and the test.

**3. Type consistency:** Module name list `_NOW_REAL` in the test matches the six `__init__.py` files edited in Step 5. The badge path string, the `467` count, and the matrix path asserted in the test are exactly the strings Step 4 must add.

**4. Review Focus:** Five listed; the top one (broken link) is pinned by `test_readme_relative_links_resolve`; the others map to the reviewer / the import-on-collection behavior / the compliance linters, as noted.

**5. Proportion:** Plan ≈ spec length; one real code block (the test). Not a transcript — the prose deliverables are specified by constraint, not written out.
