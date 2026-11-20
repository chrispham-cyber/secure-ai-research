# Phase 5 Slice 6 — Compliance Artifacts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill the three Phase-1 compliance templates (SSP, risk register, control→evidence matrix) with the real controls built in Slices 1a–5, and add a CI-enforced linter so the evidence matrix cannot drift from the code.

**Architecture:** A small pure `compliance/` package parses the evidence-matrix markdown into cited file paths and pytest node ids, then checks each exists / collects. Two new tests gate the real docs: the evidence linter (paths exist + nodes collect, RED on the unfilled template → GREEN on fill) and a no-unfilled-markers gate. The three docs are filled in place. No product code changes.

**Tech Stack:** Python 3.12, stdlib `re` + `subprocess`, pytest. Markdown docs. No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-20-phase5-slice6-compliance-artifacts-design.md`

## Global Constraints

- PUBLIC / synthetic only; local git, **no remote; no push without Chris's go**.
- Deterministic & hermetic tests (no network). The linter may run `pytest --collect-only` (local, offline); it must not reach the network.
- No changes to `retrieval/authz.py` or `research_service.py` logic. This slice adds `src/secure_ai_research/compliance/` + docs + tests only.
- **No baseline/ATO/CMMC claim.** Map only controls actually implemented; status ∈ {met, partial, planned, n/a-posture}; nothing rounded up.
- SBOM/supply-chain is Slice 7 — the SR row is status `planned (Slice 7)`.
- Test command: `./.venv/bin/pytest -q -m "not integration"`.
- Every commit ends with the attribution footer (Opus 4.8 + `Claude-Session`). Merge to main **local**.

## Review Focus

1. **Backticked non-path token with `/` (e.g. a URL `https://nvd.nist.gov/…`)** cited in the matrix would be misclassified as a repo file path and fail the linter spuriously. Parser must ignore tokens containing `://` or whitespace. — pinned by a parser test in Task 1.
2. **A cited node that collects but fails** passes the linter (collect-only ≠ pass). This is by design (see spec §5.5 ruling): the same CI run executes those tests, so a failure is never silent. — documented; the marker/linter do not re-run.
3. **Empty or placeholder evidence cell** (`…`) yields no citations → a vacuous green. The real-matrix test asserts a floor on rows/citations. — pinned by a min-citations assertion in Task 3.
4. **Parametrized node id** (`tests/test_x.py::test_y[case]`) must still classify as a node and collect. — pinned by a parser test in Task 1 and tolerated by the per-node fallback in Task 2.
5. **Marker gate only catches the three named boilerplate markers**, not a leftover prose-italic prompt. Substantive accuracy is the builder's + opus-xhigh reviewer's job. — documented.

---

### Task 1: Evidence-matrix parser

**Files:**
- Create: `src/secure_ai_research/compliance/__init__.py` (empty package marker)
- Create: `src/secure_ai_research/compliance/evidence.py`
- Test: `tests/test_evidence.py`

**Interfaces:**
- Produces: `Citations` = `NamedTuple(files: frozenset[str], test_nodes: frozenset[str])`; `parse_evidence_matrix(markdown: str) -> Citations`.

- [ ] **Step 1: Write the failing test** in `tests/test_evidence.py`:

```python
from secure_ai_research.compliance.evidence import Citations, parse_evidence_matrix

_MATRIX = """
| Control | Claim | Evidence artifact | Where | Verified by |
|---------|-------|-------------------|-------|-------------|
| AC-3 | Authorize-before-retrieve | `src/secure_ai_research/retrieval/authz.py` | `tests/test_authz.py::test_unknown_role_is_denied` | test |
| SI-10 | Input URL is NVD | see `https://nvd.nist.gov/vuln/detail/CVE-x` | `tests/test_nvd_source.py::test_url[CVE-1]` | test |
| SC-7 | Loopback | `sslmode=require` enforced | config review | review |
"""

def test_parse_extracts_paths_and_nodes_ignoring_prose_and_urls():
    c = parse_evidence_matrix(_MATRIX)
    assert c.files == frozenset({"src/secure_ai_research/retrieval/authz.py"})
    assert c.test_nodes == frozenset({
        "tests/test_authz.py::test_unknown_role_is_denied",
        "tests/test_nvd_source.py::test_url[CVE-1]",
    })
    # a URL with '/' is NOT a repo path; prose 'sslmode=require' is neither
    assert not any("nvd.nist.gov" in f for f in c.files)
    assert "sslmode=require" not in c.files
```

- [ ] **Step 2: Run to verify it fails** — `./.venv/bin/pytest tests/test_evidence.py -q`. Expected: FAIL (module `compliance.evidence` missing).

- [ ] **Step 3: Implement** `parse_evidence_matrix` in `src/secure_ai_research/compliance/evidence.py`. Approach: iterate markdown lines; keep only table-data rows (line starts with `|` and is not the header or the `---` separator). Extract every backticked span with `re.findall(r"`([^`]+)`", line)`. Classify each token `t`: skip if `"://" in t` or any whitespace in `t`; elif `re.fullmatch(r"tests/.+\.py::.+", t)` → test node; elif `"/" in t` → file path; else ignore. Return `Citations(frozenset(files), frozenset(nodes))`. Use `from __future__ import annotations` and `typing.NamedTuple`.

- [ ] **Step 4: Run to verify it passes** — same command. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/secure_ai_research/compliance/ tests/test_evidence.py
git commit -m "feat(compliance): evidence-matrix citation parser (Slice 6 Task 1)"
```

---

### Task 2: Existence + collection checkers

**Files:**
- Modify: `src/secure_ai_research/compliance/evidence.py`
- Test: `tests/test_evidence.py` (add)

**Interfaces:**
- Consumes: `Citations` from Task 1.
- Produces: `missing_files(files: Iterable[str], repo_root: Path) -> list[str]`; `uncollectable_nodes(nodes: Iterable[str], repo_root: Path) -> list[str]`.

- [ ] **Step 1: Write the failing tests** in `tests/test_evidence.py`:

```python
from pathlib import Path
from secure_ai_research.compliance.evidence import missing_files, uncollectable_nodes

def test_missing_files_lists_only_absent(tmp_path):
    (tmp_path / "there.py").write_text("x = 1\n")
    assert missing_files(["there.py", "gone.py"], tmp_path) == ["gone.py"]

def test_uncollectable_nodes_flags_absent_node(tmp_path):
    (tmp_path / "test_tmp.py").write_text("def test_ok():\n    pass\n")
    assert uncollectable_nodes(["test_tmp.py::test_ok"], tmp_path) == []
    assert uncollectable_nodes(["test_tmp.py::test_nope"], tmp_path) == ["test_tmp.py::test_nope"]
```

- [ ] **Step 2: Run to verify it fails** — `./.venv/bin/pytest tests/test_evidence.py -q`. Expected: FAIL (names not defined).

- [ ] **Step 3: Implement** both in `evidence.py`:
  - `missing_files`: `return sorted(f for f in files if not (repo_root / f).exists())`.
  - `uncollectable_nodes`: materialise `nodes` to a list; if empty return `[]`. Run one `subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", *nodes], cwd=repo_root, capture_output=True, text=True)`; if `returncode == 0` return `[]`. Otherwise identify precisely: for each node run the same command with that single node and collect those with non-zero return code; `return sorted(bad)`. No network; `check` not set.

- [ ] **Step 4: Run to verify it passes** — same command. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/secure_ai_research/compliance/evidence.py tests/test_evidence.py
git commit -m "feat(compliance): file-exists + node-collect checkers (Slice 6 Task 2)"
```

---

### Task 3: Fill the evidence matrix + real-matrix gate

**Files:**
- Modify: `documentation/assessment-evidence/control-evidence-matrix.md`
- Test: `tests/test_control_evidence.py`

**Interfaces:**
- Consumes: `parse_evidence_matrix`, `missing_files`, `uncollectable_nodes` from Tasks 1–2.

- [ ] **Step 1: Write the failing test** `tests/test_control_evidence.py`:

```python
from pathlib import Path
from secure_ai_research.compliance.evidence import (
    missing_files, parse_evidence_matrix, uncollectable_nodes,
)

_REPO = Path(__file__).resolve().parents[1]
_MATRIX = _REPO / "documentation/assessment-evidence/control-evidence-matrix.md"

def test_every_cited_path_exists_and_every_cited_node_collects():
    c = parse_evidence_matrix(_MATRIX.read_text(encoding="utf-8"))
    # not vacuous: the matrix must actually cite the system's controls
    assert len(c.files) >= 8, "evidence matrix cites too few files — is it filled?"
    assert len(c.test_nodes) >= 6, "evidence matrix cites too few tests — is it filled?"
    assert missing_files(c.files, _REPO) == []
    assert uncollectable_nodes(c.test_nodes, _REPO) == []
```

- [ ] **Step 2: Run to verify it fails** — `./.venv/bin/pytest tests/test_control_evidence.py -q`. Expected: FAIL (template cites `src/…/…` placeholder paths that don't exist / too few real citations).

- [ ] **Step 3: Fill** `control-evidence-matrix.md`. Replace the template rows with real rows, one per implemented control, each citing a **real** repo path (contains `/`, no ellipsis) and a **real** pytest node id. Cover at least: AC-3 (authz) → `src/secure_ai_research/retrieval/authz.py` + a `tests/test_authz.py::…` node; AU-3/AU-10 (signed audit) → `src/secure_ai_research/audit/signing.py` + `tests/test_audit_signing.py::…`; IA-2/IA-8 (OIDC identity) → `src/secure_ai_research/identity/…` + `tests/test_identity_*.py::…`; IA-5/SC-28 (secret mgmt) → `src/secure_ai_research/secret/verify.py` + `tests/test_verify_secrets.py::…`; SC-8/SC-13 (transit posture + at-rest cipher) → `src/secure_ai_research/transit.py` + `tests/test_transit.py::…`; SC-5 (rate limit) → `src/secure_ai_research/agents/rate_limit.py` + `tests/test_rate_limit.py::…`; SI-10/SI-4 (injection harness, schema) → `src/secure_ai_research/ai_security/…` + `tests/test_injection_harness.py::…`; SR-3 (SBOM) → status **planned (Slice 7)**, evidence `documentation/sbom/sbom-guide.md` (a doc path, exists) with no test node yet. Verify each path/node as you write (`ls`, `pytest --collect-only -q <node>`). Keep the header + Guidance prose.

- [ ] **Step 4: Run to verify it passes** — `./.venv/bin/pytest tests/test_control_evidence.py -q` then the full suite `./.venv/bin/pytest -q -m "not integration"`. Expected: PASS / all green.

- [ ] **Step 5: Commit**

```bash
git add documentation/assessment-evidence/control-evidence-matrix.md tests/test_control_evidence.py
git commit -m "feat(compliance): fill control→evidence matrix + CI linter gate (Slice 6 Task 3)"
```

---

### Task 4: Fill the SSP + risk register + marker gate

**Files:**
- Modify: `documentation/system-security-plan/system-security-plan.md`
- Modify: `documentation/risk-assessment/risk-register.md`
- Test: `tests/test_compliance_docs.py`

- [ ] **Step 1: Write the failing test** `tests/test_compliance_docs.py`:

```python
from pathlib import Path
import pytest

_REPO = Path(__file__).resolve().parents[1]
_DOCS = [
    "documentation/system-security-plan/system-security-plan.md",
    "documentation/risk-assessment/risk-register.md",
    "documentation/assessment-evidence/control-evidence-matrix.md",
]
_MARKERS = ["TEMPLATE", "_…_", "Unfilled template", "Fill in Phase 5", "Fill each section in Phase 5"]

@pytest.mark.parametrize("doc", _DOCS)
def test_no_unfilled_template_markers(doc):
    text = (_REPO / doc).read_text(encoding="utf-8")
    present = [m for m in _MARKERS if m in text]
    assert present == [], f"{doc} still has template markers: {present}"
```

- [ ] **Step 2: Run to verify it fails** — `./.venv/bin/pytest tests/test_compliance_docs.py -q`. Expected: FAIL (SSP + risk register still carry `TEMPLATE`, `_…_`, `Fill … in Phase 5`).

- [ ] **Step 3: Fill** the SSP and the risk register.
  - SSP: fill all six sections. §1 identification (name "Secure AI Research Platform", version = current, owner, PUBLIC/synthetic purpose). §2 boundary — reuse `architecture/data-flow.md` + `architecture/trust-boundaries.md`. §3 control table — one row per family (AC/AU/CM/IA/SC/SI/SR/IR) with a real one-line "how" + honest status, pointing at `security-controls/<family>/` and `src/secure_ai_research/<pkg>/`. §4 risk summary → link the register. §5 roles → `infrastructure/identity/roles.md`. §6 continuous monitoring → threat-model re-review triggers + the CI suite. Delete every italic prompt as you write.
  - Risk register: one row per threat `T1…T19` from `architecture/threat-model.md`, with L×I matching the threat model, treatment linking the implementing control, owner, status. Record accepts (owner + reason), including the deferred live-fetch timing side-channel.
  - Re-verify the matrix (filled in Task 3) still passes the marker gate.

- [ ] **Step 4: Run to verify it passes** — `./.venv/bin/pytest tests/test_compliance_docs.py -q` then the full suite. Expected: PASS / all green.

- [ ] **Step 5: Commit**

```bash
git add documentation/system-security-plan/system-security-plan.md documentation/risk-assessment/risk-register.md tests/test_compliance_docs.py
git commit -m "feat(compliance): fill SSP + risk register + no-marker gate (Slice 6 Task 4)"
```
