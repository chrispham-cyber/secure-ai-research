# black Dev-Tool Advisory Bump — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Floor the dev-only formatter `black` at 26.10.1 (clears PYSEC-2026-2120/2121 + CVE-2026-114134), reformat the 4 files black-26 flags, and regression-guard it — with the runtime lock and release SBOM byte-identical.

**Architecture:** A dev-dependency bump + a mechanical, black-deterministic reformat of 4 files. No runtime code/lock change; black is absent from `requirements.txt` and the release SBOM, so `sbom/` is untouched.

**Tech Stack:** Python 3.12, `.venv/bin/python`, pip-tools, black, pip-audit, pytest.

**Spec:** docs/superpowers/specs/2026-11-20-dev-black-advisory-bump-design.md

## Global Constraints

- `requirements.txt` (runtime lock) AND `sbom/release-sbom.cdx.json` / `sbom/sbom.manifest.json` stay **byte-identical** — `git diff --exit-code requirements.txt sbom/` clean at every commit (black is dev-only).
- `pyproject.toml` dev extra pins `black>=26.10.1,<27.0`.
- `./.venv/bin/black --check src tests` is clean after the reformat.
- `src/secure_ai_research/retrieval/authz.py` and `research_service.py` logic byte-untouched (not reformatted by black-26; confirm they are not in the diff).
- Hermetic suite green: `./.venv/bin/pytest -q -m "not integration"`.

## Review Focus

- **Runtime lock + SBOM untouched.** black is dev-only; a diff in `requirements.txt` or `sbom/` is a failure. (Task 1 `git diff --exit-code`.)
- **Reformat is behavior-preserving + minimal.** Only the 4 black-flagged files change, and the full suite stays green after. (Task 1 suite run.)
- **Floor clears ALL THREE advisories.** `black >= 26.10.1` (the binding `CVE-2026-114134` fix), not merely `26.3.1`. (Task 1 guard + pip-audit.)
- **The guard catches a revert.** `test_black_advisory_is_fixed` must FAIL if a future re-lock drops black below 26.10.1. (Task 1 RED→GREEN.)
- **objectstore.py reformat is cosmetic.** The reformatted `raise ObjectStoreError(...)` line must preserve the exact exception type/message/`from exc` chain. (Task 1 — existing objectstore tests cover it.)

---

### Task 1: Bump black, re-lock, reformat, guard

**Files:**
- Modify: `pyproject.toml` (dev extra black specifier)
- Modify: `requirements-dev.txt` (regenerated)
- Modify: `src/secure_ai_research/storage/objectstore.py`, `tests/test_benchmark_generator_param.py`, `tests/test_model_eval_seam.py`, `tests/test_generator_wiring.py` (black-reformatted)
- Modify: `tests/test_dev_lock.py` (add the black guard)

- [ ] **Step 1: Add the failing guard** to `tests/test_dev_lock.py`:

```python
def test_black_advisory_is_fixed():
    # PYSEC-2026-2120/2121 (26.3.x) + CVE-2026-114134 (26.10.1)
    assert _pinned("black") >= Version("26.10.1")
```

- [ ] **Step 2: Run it to verify it fails**

Run: `./.venv/bin/pytest tests/test_dev_lock.py::test_black_advisory_is_fixed -q`
Expected: FAIL — black is pinned 25.12.0 (< 26.10.1).

- [ ] **Step 3: Lift the floor in `pyproject.toml`**

Change `black>=24.10,<27.0` → `black>=26.10.1,<27.0`. Touch nothing else.

- [ ] **Step 4: Re-lock + install the dev set**

Run: `./.venv/bin/pip-compile --extra=dev --output-file=requirements-dev.txt --strip-extras --upgrade-package black pyproject.toml`
Then: `./.venv/bin/pip install -r requirements-dev.txt`
Expected: `black==26.10.1` pinned (already installed during recon).

- [ ] **Step 5: Reformat the 4 files**

Run: `./.venv/bin/black src tests`
Expected: `4 files reformatted, 152 files left unchanged` (or all-unchanged on a re-run).
Then: `./.venv/bin/black --check src tests` → Expected: clean (exit 0, "All done").

- [ ] **Step 6: Run the guard + the full suite to verify GREEN**

Run: `./.venv/bin/pytest tests/test_dev_lock.py::test_black_advisory_is_fixed -q` → Expected: PASS.
Run: `./.venv/bin/pytest -q -m "not integration"` → Expected: PASS (reformat preserved behavior).

- [ ] **Step 7: Verify the Global Constraints**

Run: `git diff --exit-code requirements.txt sbom/` → Expected: clean (exit 0 — black dev-only, SBOM untouched).
Run: installed-env advisory check — `./.venv/bin/pip-audit 2>&1 | grep -i '^black ' || echo "NO black advisory"` → Expected: `NO black advisory`.

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml requirements-dev.txt tests/test_dev_lock.py \
  src/secure_ai_research/storage/objectstore.py tests/test_benchmark_generator_param.py \
  tests/test_model_eval_seam.py tests/test_generator_wiring.py
git commit -m "build(deps): bump black to 26.10.1, clear dev advisory + reformat"
```

---

### Task 2: Update the supply-chain sign-off

**Files:**
- Modify: `security-controls/supply-chain/sbom.md`

- [ ] **Step 1: Resolve the black residual**

In `security-controls/supply-chain/sbom.md`: the `black==25.12.0` residual note (in the pip-audit item) and the Future-work black follow-up become **resolved** — locked `black==26.10.1`, advisory cleared, regression-guarded in `tests/test_dev_lock.py`. Do not cite a non-existent path/node (Slice-6 evidence linter).

- [ ] **Step 2: Run the full hermetic suite**

Run: `./.venv/bin/pytest -q -m "not integration"`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add security-controls/supply-chain/sbom.md
git commit -m "docs(sbom): sign off the black advisory fix"
```

---

## Final

Whole-branch opus-xhigh review (package via `review-package`, MERGE_BASE = `main@b13c0ad`); re-grade by effect; Critical/Important → one TDD fix pass; Minor → ledger. Then superpowers:finishing-a-development-branch: merge to `main` locally, verify green, delete branch + workspace, push to `origin` (private).
