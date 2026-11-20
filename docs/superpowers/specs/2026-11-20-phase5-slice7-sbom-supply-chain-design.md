# Phase 5 Slice 7 — SBOM in the release pipeline + supply-chain checklist (design)

**Date:** 2026-11-20 · **Status:** approved (Chris, Approach 1) · **ROADMAP:** Week 20 (final slice
of the Phase-5 8-slice batch) · **Branch:** `phase5-slice7-sbom-supply-chain` off `main@71be2cd`.

## Intent & why
Week 20 asks for a "**signed** SBOM" and a "supply-chain checklist **signed off**." The supply-chain
*infrastructure* already exists (SBOM script, `make sbom`, pinned `requirements*.txt`, pip-audit +
SBOM in CI, gitleaks, Dependabot, a written checklist, `security-controls/supply-chain/`), but every
piece is **best-effort and untested**: the CI SBOM/pip-audit steps are `continue-on-error`, the SBOM
is generated from the *live venv* (`cyclonedx-py environment` → 104 components incl. dev tools, with
a per-run `timestamp`/`serialNumber` so it is **not reproducible**), and the per-release checklist is
unfilled `- [ ]`. Nothing *pins* the bill of materials or *fails* when dependencies drift.

This slice makes the release SBOM **reproducible, integrity-pinned, test-gated, and signed off** —
realising "signed SBOM" the way the rest of this repo realises integrity: a **SHA-256 digest**
committed to the tree and verified by a hermetic test (the Slice-5 tamper-evidence idiom), wired into
the Slice-6 evidence linter so **SR-3 stops being "planned" and becomes enforced**.

## Goals
1. A **reproducible release SBOM** built from the pinned runtime lock `requirements.txt` (not the live
   venv), via `cyclonedx-py requirements --output-reproducible`. Verified offline + byte-deterministic.
2. An **integrity pin**: a committed `sbom/sbom.manifest.json` recording the SBOM's canonical SHA-256
   + component count + source. A hermetic test regenerates from the lock and fails if the digest
   diverges → **a dependency change that is not re-attested turns CI red**.
3. A **completeness** guarantee: every pinned runtime dependency in `requirements.txt` appears as an
   SBOM component (PEP 503-normalized name match).
4. **SR-3 flipped "planned" → "met"** in the Slice-6 control→evidence matrix, citing the real module +
   tests, so the existing `test_control_evidence.py` linter enforces the citations stay live.
5. The per-release **checklist signed off** for v0.1.0 (dated attestation, not empty checkboxes), and
   the SBOM docs updated to the reproducible release form.

## Non-goals
- **No real cryptographic signing** (cosign/sigstore/GPG). That needs network + a key/OIDC identity,
  which breaks the deterministic/offline posture. "Signed" here = committed SHA-256 integrity pin +
  human sign-off; cryptographic attestation is named as future work.
- **No new runtime dependency.** The `supply_chain` module shells out to the dev-time `cyclonedx-py`
  CLI via `subprocess` (exactly as `compliance/evidence.py` shells out to `pytest`); it imports no new
  package at runtime, and the default/base install is unchanged.
- **pip-audit stays advisory/non-gating.** It needs the online PyPI advisory DB, so it cannot be a
  hermetic gate; it remains `continue-on-error` in CI, unchanged.
- No change to `retrieval/authz.py` or `research_service.py`.

## Anti-goals (would make this a failure even if green)
- A drift gate that passes when a dependency silently changes (the whole point is it must fail).
- A "reproducible" claim that is actually non-deterministic (tool emits a timestamp/UUID) — must be
  proven by a two-run equality test, not asserted.
- A completeness check that false-passes on PyPI name case/separator variance (`FastAPI` vs `fastapi`,
  `typing_extensions` vs `typing-extensions`) — must PEP 503-normalize both sides.
- A gate so brittle it reddens on a cyclonedx-py version bump rather than a real component change.

## Constraints (posture)
Deterministic/offline/stdlib default; PUBLIC/synthetic; real tooling behind a subprocess seam; TDD
(RRGR, watch each test fail first); final opus-xhigh whole-branch review; merge-to-main-local; **no
push**. Attribution footer on every commit.

## Approaches considered
- **Approach 1 — reproducible SBOM from the lock + SHA-256 integrity pin + hermetic drift/completeness
  gate + signed-off checklist (CHOSEN).** Makes "signed SBOM / signed off" concrete and testable in
  posture, reuses the repo's SHA-256 integrity idiom, and plugs into the Slice-6 linter. Cost: a
  dependency change now requires regenerating the SBOM + manifest (`make sbom-release`) and committing
  it — which is exactly the drift control we want.
- **Approach 2 — keep best-effort; add a well-formedness test, fill docs, SR-3 → "partial".** Lighter,
  but delivers no *pin* and no *drift gate*, so "signed/signed-off" is not really met. Rejected: it
  documents a control instead of enforcing one, against the batch's whole discipline.
- **Approach 3 — real cryptographic signing (cosign/sigstore).** Rejected: network + key management
  violate the offline/deterministic default. Recorded as future work in the checklist.

## Design (the how, as decided)

### Verified premise (recon)
`cyclonedx-py requirements requirements.txt --output-reproducible --of json` runs **offline**, emits
**24 runtime components**, carries **no `timestamp` and no `serialNumber`**, and is **byte-identical
across runs**. So reproducibility is a property of the tool flag (confirmed), not something we must
hand-roll — the module still projects to a canonical component set before hashing, to stay robust to
a future cyclonedx-py formatting bump.

### New module `src/secure_ai_research/supply_chain/`
`__init__.py` (docstring) + `sbom.py`:
- `generate_release_sbom(requirements_path: Path, repo_root: Path) -> bytes` — subprocess
  `cyclonedx-py requirements <requirements_path> --output-reproducible --of json -o -` (stdout),
  returns raw bytes; non-zero exit → `SbomError`. No network, no new import.
- `canonical_components(sbom_bytes: bytes) -> list[dict]` — parse JSON, return
  `sorted({name, version, purl})` by (name, version); the stable projection the digest is taken over.
- `sbom_digest(sbom_bytes: bytes) -> str` — `sha256(json.dumps(canonical_components(...),
  sort_keys=True, separators=(",",":")).encode())` hexdigest. Robust to tool formatting; sensitive to
  any real component add/remove/version change.
- `pinned_requirements(requirements_path: Path) -> set[str]` — PEP 503-normalized distribution names
  from the lock: parse `name[extras]==version` lines; skip blanks, comments, `-r`/`-c`/`-e` includes,
  `--hash=` continuation lines, and environment markers (`; python_version …`).
- `missing_components(requirements_path, sbom_bytes) -> list[str]` — normalized pinned names absent
  from the SBOM's normalized component names, sorted.
- `_normalize(name) -> str` — PEP 503: lowercase, collapse runs of `-_.` to a single `-`.
- `read_manifest(path) -> dict` — load the committed manifest.
- `SbomError(RuntimeError)`.

### Committed artifacts
- `sbom/release-sbom.cdx.json` — the reproducible release SBOM (auditable artifact; regenerable).
- `sbom/sbom.manifest.json` — `{"source": "requirements.txt", "tool": "cyclonedx-py requirements
  --output-reproducible", "sbom_sha256": "<canonical digest>", "component_count": 24, "sbom_file":
  "sbom/release-sbom.cdx.json"}`. This is the "signature": the pinned bill of materials.
- `.gitignore`: keep ignoring the ad-hoc `sbom.json` (the `environment` dev convenience); the new
  `sbom/` release artifacts are committed on purpose.

### Tests `tests/test_sbom.py` (hermetic; cyclonedx-py is a dev dep, always present in dev/CI)
- `test_release_sbom_is_reproducible` — generate twice, assert raw bytes identical (proves the flag).
- `test_committed_sbom_matches_regeneration` — canonical digest of a fresh gen == canonical digest of
  committed `sbom/release-sbom.cdx.json` (drift gate; tolerant of tool formatting bumps).
- `test_manifest_digest_matches_committed_sbom` — `sbom_digest(committed SBOM)` ==
  `manifest["sbom_sha256"]`, and `component_count` matches (the pin is honest).
- `test_sbom_covers_every_pinned_runtime_dependency` — `missing_components(requirements.txt, committed
  SBOM) == []` (completeness; this is the SR-3 evidence node).
- `test_sbom_is_well_formed_cyclonedx` — valid JSON, `bomFormat == "CycloneDX"`, every component has
  non-empty `name`, `version`, `purl`.
- Unit tests for the parsing helpers on synthetic fixtures: `pinned_requirements` handles
  `pkg[extra]==1.0`, `--hash` lines, `-r base.txt`, comments, markers; `_normalize` maps
  `Typing_Extensions` and `typing-extensions` equal; `missing_components` flags an absent dep and
  passes on a case/separator variant; `canonical_components`/`sbom_digest` are order-independent;
  `generate_release_sbom` raises `SbomError` on a bad requirements path.

### Wiring
- **Evidence matrix** (`documentation/assessment-evidence/control-evidence-matrix.md`): SR-3 row →
  status **met**, evidence `src/secure_ai_research/supply_chain/sbom.py`, verified by
  `tests/test_sbom.py::test_sbom_covers_every_pinned_runtime_dependency` (+ the reproducibility node).
  The Slice-6 `test_control_evidence.py` then enforces these citations exist + collect, and
  `skip_marked_nodes` guards them from being skip-disabled. Keep the `documentation/sbom/sbom-guide.md`
  path citation too. (Marker gate still passes — no template strings introduced.)
- **Makefile**: add `sbom-release` → generate the reproducible SBOM + rewrite the manifest (the
  re-attest command). Keep `make sbom` (environment) as the quick dev-inventory convenience.
- **Docs**: `security-controls/supply-chain/sbom.md` — document the reproducible release SBOM + the
  manifest pin + the drift gate; replace the per-release `- [ ]` with a **dated v0.1.0 sign-off**
  section (lock reviewed, pip-audit reviewed, SBOM produced + pinned, gitleaks clean, model hashes
  verified, base images pinned), and name cryptographic signing as future work.
  `documentation/sbom/sbom-guide.md` — update generation command + describe the manifest/digest gate.
  `scripts/gen-sbom.sh` — leave `environment` (dev) and point to `make sbom-release` for the pinned one.
- **CI** (`.github/workflows/ci.yml`): the gate is delivered by the existing `pytest -m "not
  integration"` step (it runs `test_sbom.py`). Repoint the best-effort `SBOM (CycloneDX)` step to the
  reproducible release form for the uploaded artifact; leave pip-audit advisory/non-gating. Minimal
  churn — the tests are the enforcement.

### What's left to the builder
- Confirm the exact `-o -` stdout form vs writing a temp file for `cyclonedx-py requirements`; if
  stdout is unavailable, write to a temp path and read it back (builder's call, behavior identical).
- Exact JSON field presence (`purl`) per the installed cyclonedx-bom version — assert what the real
  tool emits (Task 1 reads one real SBOM first).
- Checklist prose/wording for the sign-off section.

## Review focus (carry into the plan)
1. **Reproducibility is proven, not assumed** — two-run byte-equality; if a future tool flag regresses,
   the test catches it.
2. **`cyclonedx-py requirements` is offline** — no network in the hermetic test (verified in recon;
   re-assert in Task 1). If it ever needs the network, the test must move to `-m integration`.
3. **PEP 503 name normalization** on both sides of the completeness check (case + `-_.`), or `fastapi`
   vs `FastAPI`-class false negatives slip through.
4. **requirements.txt parsing** ignores `--hash=` lines, `-r/-c/-e` includes, comments, blanks, and
   env markers — a lock line misread as a package name false-fails completeness.
5. **The drift gate actually fails on drift** — a changed/added/removed component without a re-attested
   manifest must redden `test_committed_sbom_matches_regeneration` / `test_manifest_digest_matches…`.
