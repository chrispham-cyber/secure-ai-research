# black Dev-Tool Advisory Bump — Design

**Status:** approach approved by Chris ("go", 2026-11-20); short design (a small change)
**Date:** 2026-11-20
**Branch:** `dev-black-advisory-bump` off `main@b13c0ad`
**Relation:** closes the one residual the cyclonedx-bom-bump slice disclosed — the pre-existing dev-only `black==25.12.0` advisory.

---

## Intent / why

The previous slice's installed-env `pip-audit` surfaced three advisories on the dev-only formatter `black==25.12.0`: `PYSEC-2026-2120` (fixed 26.3.0), `PYSEC-2026-2121` (fixed 26.3.1), and `CVE-2026-114134` (fixed **26.10.1**). It was disclosed honestly and deferred as out-of-scope. Chris elected to clear it now. Flooring `black` at the version that fixes **all three** (26.10.1) clears the advisory.

## Recon findings

1. **`black 26.10.1` exists** (this env's latest `<27`) and fixes all three advisories (the binding one is `CVE-2026-114134` → 26.10.1).
2. **`black` is dev-only** — not in `requirements.txt` nor the release SBOM (`sbom/`). So this slice makes **no runtime-lock and no SBOM change / re-attestation**.
3. **black 26.10.1 reformats 4 of 156 files** (`src/.../storage/objectstore.py`, `tests/test_benchmark_generator_param.py`, `tests/test_model_eval_seam.py`, `tests/test_generator_wiring.py`). The changes are purely black-26's updated line-wrapping heuristics (collapsing/expanding call & signature wraps) — behavior-preserving. CI runs `black --check`, so the bump **requires** reformatting these 4 (otherwise CI reddens). Reformatting them is the necessary completion of the approved bump, not a scope expansion.

## Goals

1. `black` floored `>=26.10.1,<27.0`; dev lock re-locked; installed `.venv` matches.
2. The 4 files reformatted so `black --check src tests` is clean (CI stays green).
3. The advisory cleared (installed-env `pip-audit` no longer lists `black`); regression-guarded in `tests/test_dev_lock.py`.
4. Runtime lock (`requirements.txt`) and the release SBOM (`sbom/`) **byte-identical** (black is dev-only).

## Non-goals / anti-goals

- No runtime dependency / behaviour change; no `src/…/{authz,research_service}.py` logic edits (only objectstore.py's mechanical reformat).
- No SBOM change — black is absent from the release set, so no re-attestation.
- No cryptographic SBOM signing (still Future work).
- No broader reformat — only the 4 files black-26 flags; do not hand-edit formatting.

## Constraints

- Deterministic/offline default; network dev-time only (`pip-compile`/`pip install`, `pip-audit` advisory DB).
- Hermetic suite green: `./.venv/bin/pytest -q -m "not integration"` (466 + the new guard assertion).
- Reformat must be behavior-preserving — proven by the full suite staying green after it.
- Gates kept: TDD + opus-xhigh whole-branch review + merge-to-main-local, then push to `origin` (private).

## Approaches considered

**A. Floor at 26.10.1 (the all-advisories fix), re-lock, reformat the 4 files (chosen).** The minimal correct bump: clears all three advisories and keeps CI's `black --check` green. One coherent commit set.

**B. Floor at 26.3.1 (clears only the two PYSEC).** Rejected — leaves `CVE-2026-114134` open; pip-compile would pick the latest `<27` (26.10.1) anyway, so the lower floor is a weaker guard for no benefit.

**C. Bump + raise the cap past 27.** Rejected — out of scope; the existing `<27.0` cap already admits 26.10.1. Major-cap changes deserve their own review.

## The how (decided design)

1. **pyproject + re-lock.** `black>=24.10,<27.0` → `black>=26.10.1,<27.0`; `pip-compile` the dev set; `pip install -r requirements-dev.txt`. (black 26.10.1 already installed during recon.)
2. **Reformat.** `./.venv/bin/black src tests` → reformats exactly the 4 flagged files. Verify `black --check src tests` clean.
3. **Regression guard.** Extend `tests/test_dev_lock.py` with `test_black_advisory_is_fixed` asserting the locked `black >= 26.10.1` — RED today (25.12.0), GREEN after the re-lock.
4. **Verify.** `git diff --exit-code requirements.txt sbom/` clean; installed-env `pip-audit` no longer lists `black`; full suite green.
5. **Sign-off.** `security-controls/supply-chain/sbom.md`: turn the `black` residual / Future-work note into resolved (locked `26.10.1`, advisory cleared).

## Decision

- **Reformatting the 4 files is in-scope** — it is the unavoidable completion of a `black` bump under a `black --check` CI gate, done mechanically by black itself (no hand edits). Ledgered as a ruling.

## What's left to the builder
The exact re-lock transitive churn (dev-only) and the precise reformatted bytes (black-deterministic) — both mechanical once the floor is set.
