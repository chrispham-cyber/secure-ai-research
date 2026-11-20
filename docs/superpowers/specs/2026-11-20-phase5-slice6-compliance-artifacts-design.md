# Phase 5 Slice 6 — Compliance Artifacts (SSP + Risk Register + Control→Evidence Matrix), CI-verified

> Scope: PUBLIC / synthetic data only. This slice produces documentation + a verification
> test. It is **not** an authorization package and claims **no ATO / CMMC / baseline
> completeness**.

**Status:** design, awaiting approval.
**Slice:** Phase 5, Slice 6 of the 8-slice batch = **ROADMAP Week 19**.
**Branch:** `phase5-slice6-compliance-artifacts` off `main@27ef43a` (local, no remote).

## 1. Intent & why

Phase 1 left three **template** compliance docs under `documentation/`:
`system-security-plan/system-security-plan.md`, `risk-assessment/risk-register.md`, and
`assessment-evidence/control-evidence-matrix.md`. Week 19's deliverable is to **fill them
in** — now that Slices 1a–5 have built the real controls (RBAC/ABAC authorize-before-retrieve,
OIDC identity, tamper-evident signed audit, secret management, at-rest Cipher seam, in-transit
posture gate, rate limiting, prompt-injection harness).

The evidence matrix states its own governing principle: *"Implemented without evidence is a
claim, not assurance."* The on-posture way to honor that — and to match the platform's whole
"deterministic, verifiable, no false green" ethos — is to make the evidence matrix
**machine-checkable**: a test parses it and fails CI if any cited file is missing or any cited
test no longer collects. The compliance docs then cannot silently drift from the code.

## 2. Goals / Non-goals / Anti-goals

**Goals**
- Fill the **SSP** with the real system: identification, environment & boundary (reusing the
  existing DFD/trust-boundary docs), a control-implementation table across the NIST 800-53
  families already in the template (AC, AU, CM, IA, SC, SI, SR, IR) with **honest status**
  (met / partial / planned / N-A-for-posture), risk summary, roles, continuous monitoring.
- Fill the **risk register**, seeded from the STRIDE threat model (T1–T19), each threat → one
  or more rows with Likelihood×Impact (1–3) → Low/Med/High/Critical and a treatment that links
  the implementing control.
- Fill the **control→evidence matrix**: each control claimed in the SSP → an evidence artifact
  (a real file + a real test node / CI job), with its location and how it is verified.
- Add a **CI-enforced evidence linter** (`compliance/evidence.py` + `tests/test_control_evidence.py`)
  that parses the real matrix and asserts every cited repo path exists and every cited test
  node collects. Runs in the normal (non-integration) suite, which `ci.yml` already executes.
- Add a light **no-unfilled-markers gate** so none of the three docs ships with leftover
  template prompts.

**Non-goals**
- SBOM / supply-chain tooling — that is **Slice 7 / Week 20**. The SR family + its matrix row
  are documented here with honest status **planned (Slice 7)**.
- New product code or new controls. This slice **documents what exists**; a partial control is
  labelled partial, not quietly upgraded.

**Anti-goals** (a failure even if it "works")
- Any baseline-completeness or ATO/CMMC claim. We map **only the controls we actually
  implement** to their family/ID; we do not imply we satisfy a 800-53 Low/Moderate baseline.
- Fabricated or stale evidence: a cited test that does not exist, a path that 404s, a "met"
  status for a control that is partial. The linter exists precisely to make this fail loudly.

## 3. Constraints

- PUBLIC / synthetic only; local git, **no remote, no push without Chris's go**.
- Deterministic & hermetic tests (no network). The linter may shell out to
  `pytest --collect-only` (a local, offline operation) but must not run the network.
- Default-path posture unchanged: this slice adds a `compliance/` package and docs; it does
  **not** touch `retrieval/authz.py` or `research_service.py` logic.
- Attribution footer on every commit (Opus 4.8 + session line). Merge to main **local**.

## 4. Approaches considered

The framework and scope are **settled by the existing scaffold and the ROADMAP**, not open:
- *Framework* — the templates are already structured as NIST **800-53 control families**
  (AC/AU/CM/IA/SC/SI/SR/IR with IDs like AC-3, AU-3, SI-7). We keep that, honestly scoped.
- *Scope* — ROADMAP Week 19 = SSP + risk register + assessment-evidence templates filled in;
  SBOM (Week 20) is Slice 7. Ruled accordingly.

The one open decision was **how verifiable** the evidence is. Options weighed:

- **A — Prose + links only.** Fill the docs with accurate, clickable references, no enforcing
  test. Fastest; but citations rot silently as later slices move code. Rejected: it reproduces
  the exact "claim, not assurance" failure the matrix warns against.
- **B — Verify đầy đủ (CHOSEN).** Fill the docs **and** add a linter that asserts every cited
  path exists and every cited test node collects, run in CI. Docs cannot drift. This is a real
  TDD slice and matches the platform ethos. More work, but the work is the point.
- **C — Path-only verify.** Like B but checks only that cited files exist, not that cited tests
  collect. Lighter, but misses a renamed/removed test whose file still exists. Rejected in
  favor of B's stronger guarantee.

**Chris chose B** (2026-11-20).

## 5. Design

### 5.1 Honesty posture
Every control row carries a status from {met, partial, planned, n/a-posture}. "met" requires a
passing cited test or a concrete config artifact. "partial" is used where a control is real but
opt-in or incomplete (e.g., at-rest encryption is a seam defaulting to `NullCipher`; TLS is a
posture *check*, not termination we own). "planned" is used for SBOM (Slice 7). Nothing is
rounded up.

### 5.2 SSP (`documentation/system-security-plan/system-security-plan.md`)
Fill all six sections. The control-implementation table maps each family to its real
implementation with a one-line "how" and a status, each pointing at the relevant
`security-controls/<family>/` doc and/or `src/secure_ai_research/<pkg>/`. Secret management
(Slice 5) and the rate limiter (Phase 3) are folded in under IA-5 / SC-28 and SC-5 respectively.

### 5.3 Risk register (`documentation/risk-assessment/risk-register.md`)
One table seeded from `architecture/threat-model.md` (T1–T19). Each row: asset, threat (Txx),
L×I (1–3, matching the threat model's own ratings), risk band, treatment (mitigate/transfer/
accept/eliminate) linking the implementing control, owner, status. Accepts record owner +
reason (e.g., the deferred timing side-channel already triaged in Phase 3/5).

### 5.4 Control→evidence matrix (`documentation/assessment-evidence/control-evidence-matrix.md`)
The **machine-checked** artifact. Each row: `Control` (family-ID + name) · `Claim` · `Evidence
artifact` · `Where` · `Verified by`. Convention that makes it checkable:
- Repo paths are written as **backticked, repo-root-relative** tokens containing `/`
  (e.g. `` `src/secure_ai_research/retrieval/authz.py` ``). No ellipses.
- Test evidence is written as a **backticked pytest node id**
  (e.g. `` `tests/test_authz.py::test_unknown_role_is_denied` ``).
- Prose in backticks without a `/` or `::` (e.g. `` `sslmode=require` ``) is ignored by the
  linter.

### 5.5 Evidence linter (`src/secure_ai_research/compliance/evidence.py`)
Pure, importable, unit-tested:
- `parse_evidence_matrix(markdown: str) -> Citations` where
  `Citations = (files: frozenset[str], test_nodes: frozenset[str])`. Parses the markdown
  table rows (skips header/separator), extracts backticked tokens, classifies: a token matching
  `^tests/.+\.py::.+$` → test node; else a token containing `/` → repo path; else ignored.
- `missing_files(files, repo_root) -> list[str]` → cited paths that do not exist.
- `uncollectable_nodes(nodes, repo_root) -> list[str]` → cited node ids that a single
  `pytest --collect-only -q <nodes…>` subprocess does not report as collected (non-zero exit or
  absent from the collected set).

`tests/test_control_evidence.py` wires these to the **real** matrix file and asserts both lists
are empty. It is RED against the unfilled template (ellipsis/placeholder paths don't exist) and
GREEN once 5.4 is filled with live citations.

**Ruling (collect vs. pass).** The linter asserts cited nodes **collect** (exist + import
cleanly), not that they pass, because: (a) re-running tests from inside a test is slow and
fragile and risks self-reference; (b) every cited node is itself part of the enforced suite, so
the same CI run that executes the linter also proves those tests **pass**. Collect-in-linter +
pass-in-suite together deliver the "collect/pass" guarantee Chris chose, without nested runs.
Cost if wrong: a cited test could collect but be failing — but then CI is already red on that
test, so the gap is not silent.

**Scope ruling.** The linter checks the **evidence matrix only** (the assurance artifact). The
SSP and risk register are reviewed prose; their file references use relative markdown links
whose correctness is covered by human + opus-xhigh review and the marker gate (5.6), not the
path linter. This avoids relative-vs-root path ambiguity and keeps the linter's contract crisp.

### 5.6 No-unfilled-markers gate (`tests/test_compliance_docs.py`)
Asserts none of the three filled docs still contains a template marker — `TEMPLATE`, an unfilled
italic prompt `_…_`, or `Fill … in Phase 5`. RED against the templates, GREEN once filled.
Deterministic, hermetic.

### 5.7 CI
No new CI wiring needed: `.github/workflows/ci.yml` already runs the pytest suite, so both new
tests gate automatically. The evidence linter is an ordinary non-integration test.

## 6. What's left to the builder
- The exact prose of the SSP/risk register (accuracy is the builder's + reviewer's job).
- The specific control→evidence rows and which test node best evidences each (the builder picks
  the strongest existing test per control; the linter guarantees the pick is live).
- The exact marker-regex set in 5.6, provided the three named markers are covered.

## 7. File structure & test plan
**Create:** `src/secure_ai_research/compliance/__init__.py`, `…/compliance/evidence.py`;
`tests/test_evidence_parser.py` (parser + checker units), `tests/test_control_evidence.py`
(real-matrix gate), `tests/test_compliance_docs.py` (marker gate).
**Fill (modify):** the three `documentation/**` docs.
**Tasks (each green-at-end, TDD):**
1. `evidence.py` parser — fixture-driven units.
2. `evidence.py` checkers (`missing_files`, `uncollectable_nodes`) — units incl. a known-good and
   known-bad node.
3. Fill the evidence matrix + `test_control_evidence.py` (RED on template → GREEN on fill).
4. Fill SSP + risk register + `test_compliance_docs.py` marker gate (RED → GREEN).

Final: opus-xhigh whole-branch review → one TDD fix pass → merge to main local. No push.
