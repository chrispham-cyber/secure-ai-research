# Portfolio Polish — Design

**Date:** 2026-11-20
**Author:** Chris Pham (with Claude)
**Status:** Approved (short design; repo stays PRIVATE)
**Scope size:** Small–medium change — documentation currency, no logic changes.

## Intent & why

The platform is complete through Phase 5 Slice 7: a 6-phase, secure-by-design,
evidence-grounded AI research system with **467 hermetic unit tests + 20 integration
tests**, a STRIDE threat model, a NIST control→evidence matrix, a reproducible SBOM, and
green CI. But the **front-door documentation still describes the Phase-1 skeleton it started
as.** Anyone who opens the repo — a recruiter, a collaborator, future-Chris — reads an
"early foundation scaffold" and misses six phases of real, tested security engineering.

This slice makes the documentation tell the truth about what was built, and surfaces the
assurance evidence that already exists but is buried. It is a portfolio-facing honesty +
discoverability pass, not new product code.

## The staleness (verified 2026-11-20)

- `README.md` — **Status: "Phase 1 — foundation scaffold"**; a "What's real vs stubbed"
  table that lists ingestion/retrieval/agents/evaluation/reporting as *stubbed* (all now
  real — `authz.py` 59 ln, `vectorstore.py` 164 ln, `agents/functions.py` 83 ln,
  `reporting/report.py` 107 ln, `evaluation/metrics.py` 90 ln, `ingestion/nvd.py` 78 ln);
  the claim that `/research/*` returns **501 Not Implemented** (false — real routes exist:
  `GET /research/cve/{cve_id}`, `GET /research/attack/{technique_id}`, `POST /research/search`,
  `POST /research/ask`); repo-map annotations marking real modules "(stubs)".
- Six module docstrings say "documented stub in the starter scaffold":
  `reporting/__init__.py`, `ingestion/__init__.py`, `agents/__init__.py`,
  `ai_security/__init__.py`, `retrieval/__init__.py`, `evaluation/__init__.py`; plus
  `api/__init__.py` ("return 501 until the retrieval pipeline exists") and `api/main.py`
  ("`/research/*` — present but **501 Not Implemented**").
- `CHANGELOG.md` — only `[0.1.0] Initial starter scaffold (Phase-1 foundation)`; no record
  of Phases 2–5.
- `ROADMAP.md` intro — "Phase 1 is largely complete in this starter repo."
- `pyproject.toml` `description` — "Starter scaffold for …".

## The one honest caveat (must survive the rewrite)

The **only** intentional fail-loud stub left is `OllamaEmbedder` (local embedding via Ollama),
guarded by `tests/test_stubs.py::test_ollama_embedder_stub_raises_on_construction`. The
default `HashingEmbedder` is real, deterministic, offline. The rewrite says so plainly —
it does not claim "zero stubs," and the currency test must not ban the word "stub."

## Goals

- README leads with the real, finished security story and current status; real-vs-stub
  reflects reality; the 501 claim is gone; `/research/*` routes are described as they behave.
- A **CI badge** (green) and the **test counts** (467 unit + 20 integration) are visible.
- A **Security & Compliance** section surfaces the assurance evidence that already exists:
  threat model, control→evidence matrix (NIST AC-3/AU-10/IA-2/IA-5/SC-8/SC-28), risk
  register, SSP, SBOM guide, and the opt-in backend seams
  (`SAIR_VECTOR_STORE`/`SAIR_OBJECT_STORE`/`SAIR_AUTH`/`SAIR_CIPHER`).
- The stale "documented stub / 501" docstrings in the now-real modules are corrected, so the
  source stops contradicting the README.
- `CHANGELOG.md` records the Phase 2–5 arc; `ROADMAP.md` intro + `pyproject.toml` description
  reflect the finished state.

## Non-goals

- No logic changes anywhere. **`retrieval/authz.py` and `research_service.py` are not
  touched** (not even docstrings). Edits to other modules are docstring/comment text only.
- The existing `architecture/` docs (threat-model, data-flow, trust-boundaries, system-design)
  are **not rewritten** — they are already strong; this slice only links them better.
- No new threat model (one already exists at `architecture/threat-model.md`).
- No version bump (stays `0.1.0`; releasing/SemVer is a separate concern).
- **No making the repo public** and no public-exposure secrets sweep (gitleaks already clean;
  repo stays private per Chris).

## Anti-goals (would make this a failure even if it "worked")

- Overstating: claiming a capability that isn't real, or hiding the `OllamaEmbedder` stub, to
  look more finished. The whole point is an *honest* README; inflation defeats it.
- Breaking the compliance-doc linters (`tests/test_compliance_docs.py`,
  `tests/test_control_evidence.py`) or any backticked path / pytest node they resolve.

## Constraints

- Repo PRIVATE at `github.com/chrispham-cyber/secure-ai-research`. A GitHub Actions badge on
  a private repo renders for **authenticated viewers with repo access** (i.e. Chris on
  github.com) and resolves publicly if the repo is ever made public — acceptable; noted so
  it isn't mistaken for a broken badge.
- PUBLIC/synthetic posture; no secrets committed.
- Workflow gates unchanged: TDD → opus-xhigh whole-branch review → merge to main (local) →
  push to the private origin.

## Approaches

**A — Truth-and-currency overhaul in place (CHOSEN).** Update the README, the stale
docstrings, CHANGELOG, ROADMAP intro, and pyproject description to reflect the real 6-phase
state; add the CI badge + test counts; add a Security & Compliance section linking the
existing assurance docs. Leave the architecture docs as-is. *Trade-off:* touches ~11 files
including source docstrings — but docstring-only, low risk, and it removes the
source-vs-README contradiction.

**B — README-only rewrite (REJECTED).** Fix just the README, leave the module docstrings and
CHANGELOG stale. Faster, but a reader browsing `src/` still sees "documented stub in the
starter scaffold" on real modules — the repo contradicts its own front page. Half-honest.

**C — Full release pass: version bump to 1.0, release notes, doc restructure (REJECTED).**
Bigger: pulls in SemVer/release decisions and doc reorganization the portfolio gap doesn't
need. YAGNI — the gap is *currency*, not restructuring or releasing.

## The decided how (per file)

1. **`README.md`** — rewrite:
   - Status line → current (platform complete through Phase 5; deterministic/offline default,
     real infra behind opt-in seams; the one `OllamaEmbedder` stub named honestly).
   - CI badge + a one-line test-count statement (467 unit + 20 integration).
   - "What's real vs stubbed" → corrected to reality (almost all real; `OllamaEmbedder` the
     lone stub).
   - Quickstart `/research/*` note → describe the real routes, drop "501".
   - Repo-map annotations → drop stale "(stubs)".
   - New **Security & Compliance** section linking: `architecture/threat-model.md`,
     `documentation/assessment-evidence/control-evidence-matrix.md` (name the NIST controls),
     `documentation/risk-assessment/risk-register.md`,
     `documentation/system-security-plan/system-security-plan.md`,
     `documentation/sbom/sbom-guide.md`, and the four `SAIR_*` opt-in seams.
2. **Module docstrings** (text only): `reporting/__init__.py`, `ingestion/__init__.py`,
   `agents/__init__.py`, `ai_security/__init__.py`, `retrieval/__init__.py`,
   `evaluation/__init__.py`, `api/__init__.py`, `api/main.py` — replace "documented stub /
   501" language with an accurate one-liner; `retrieval/__init__.py` keeps the honest note
   that `OllamaEmbedder` is the remaining fail-loud stub.
3. **`CHANGELOG.md`** — add an entry (Unreleased or dated) summarizing Phases 2–5
   (RAG + endpoints, AI-specific security, evaluation/red-team, deploy/assurance:
   OIDC, audit signing, crypto seam, SBOM, compliance docs).
4. **`ROADMAP.md`** — intro line: reflect that Phases 1–5 are built.
5. **`pyproject.toml`** — `description` → finished-state wording (metadata only; version
   unchanged).

## What's left to the builder

- Exact README prose and section order (lead with the security story), within the goals
  above.
- CHANGELOG entry wording and whether to date it `[Unreleased]` or `2026-11-20`.
- The precise one-line docstring replacements.

## Verification / tests (TDD)

New hermetic test `tests/test_readme_currency.py` (RED before the rewrite, GREEN after):

- `test_readme_status_is_current` — the stale status string `Phase 1 — foundation scaffold`
  is **absent**.
- `test_readme_shows_ci_and_coverage` — README contains the CI-badge path
  (`actions/workflows/ci.yml/badge.svg`) and the unit-test count (`467`).
- `test_readme_surfaces_compliance_evidence` — README links
  `documentation/assessment-evidence/control-evidence-matrix.md`.
- `test_research_endpoints_not_described_as_501` — the stale
  `501 Not Implemented` research-endpoint claim is **absent** from the README.
- `test_now_real_module_docstrings_are_not_stale` — none of the six now-real module
  `__init__.py` docstrings contain `documented stub in the starter scaffold`.

Whole suite (`./.venv/bin/pytest -q -m "not integration"`) stays green, including
`test_compliance_docs.py`, `test_control_evidence.py`, and `test_stubs.py` (the
`OllamaEmbedder` stub is untouched).
