# SBOM Generator Bump + virtualenv Advisory Fix — Design

**Status:** approach approved by Chris ("go", 2026-11-20); short design (a small, focused change)
**Date:** 2026-11-20
**Branch:** `sbom-tool-bump-virtualenv-fix` off `main@44b4c8a`
**Relation:** closes the one item the prior hardening follow-up ruled BLOCKED — the `virtualenv` advisory fix — by removing the transitive `packaging` cap that blocked it, then re-attesting the release SBOM against the newer generator.

---

## Intent / why

The supply-chain hardening follow-up (merged, `main@44b4c8a`) found the `virtualenv` dev-tool advisory (`PYSEC-2026-4374..4383`, fixed in **21.14.9**) **unfixable in place**: every `virtualenv ≥ 21.14.9` needs `packaging ≥ 26.3`, but the pinned SBOM generator `cyclonedx-bom==5.5.0` caps `packaging < 26`. It was ruled blocked and documented. Chris elected to clear it with a dedicated, reviewed slice. This slice lifts the cap by bumping the generator, re-attests the release SBOM so its committed artifact matches the tool that now produces it, and locks in the `virtualenv` fix.

## Recon findings (decide the design)

1. **`packaging` is dev-only.** It is **not** in `requirements.txt` (the runtime lock) — only in `requirements-dev.txt:124:packaging==25.0`, pulled by dev tooling. ⇒ bumping it to `≥26.3` moves **only the dev lock**; the runtime lock and the release SBOM's component *set* (24 runtime deps) are untouched.
2. **`cyclonedx-bom 9.0.0` is feasible.** `requires-python <4,>=3.9` (OK on 3.12), keeps the `cyclonedx-py` console script, and requires `packaging <27,>=22` — so `virtualenv ≥ 21.14.9`'s `packaging ≥ 26.3` now co-resolves.

## Goals

1. **Unblock + lock in the `virtualenv` fix.** Dev lock pins `virtualenv ≥ 21.14.9`; `pip-audit` on the dev set no longer reports `PYSEC-2026-4374..4383`.
2. **Re-attest the release SBOM against the new generator.** Regenerate the committed `sbom/release-sbom.cdx.json` + `sbom/sbom.manifest.json` with `cyclonedx-bom 9.x` so the committed artifact's provenance reflects the tool that now produces it; the hermetic drift/completeness/reproducibility gate stays green under 9.x.
3. **Runtime lock unchanged.** `requirements.txt` byte-identical (proven by `git diff --exit-code`).

## Non-goals / anti-goals

- **No runtime dependency change.** All three bumped packages (`cyclonedx-bom`, `virtualenv`, `packaging`) are dev-only; `requirements.txt` must not move. A diff there is a failure of this slice.
- **No cryptographic SBOM signing (cosign/sigstore).** Still out of the offline/deterministic posture; stays Future work.
- **No change to SBOM *semantics*.** Same 24 runtime components; only the serializer/tool-metadata (and, if the spec version advances, the wrapper) changes. The digest is still the `{name,version,purl}` projection (the prior slice's documented D1 scope stands, unchanged).
- **No `src/…/{authz,research_service}.py` edits**; no runtime-path behaviour change.

## Constraints

- Deterministic/offline default. Network is dev-time only: `pip-compile` + `pip install` against PyPI, and `pip-audit`'s advisory DB. SBOM generation itself stays offline (re-verify: `cyclonedx-py` 9.x imports no network modules).
- Hermetic suite stays green: `./.venv/bin/pytest -q -m "not integration"` (464 + any new test).
- Reproducible: `cyclonedx-py requirements requirements.txt --output-reproducible --of json` must still be raw-byte-identical across runs under 9.x (the existing `test_release_sbom_is_reproducible`).
- Gates kept: TDD + opus-xhigh whole-branch review + merge-to-main-local, then **push to `origin`** (private).

## Approaches considered

**A. Bump the generator to `cyclonedx-bom 9.x` (latest major), re-attest, then bump `virtualenv` (chosen).** One coherent dependency+artifact refresh: lifting the `packaging` cap is the *only* way to reach the fix in-posture, and re-attesting keeps the committed SBOM honest about its provenance. Matches the prior slice's shape.

**B. Keep `cyclonedx-bom 5.5.0`; pin `virtualenv` to the last pre-advisory `packaging<26`-compatible version.** Rejected — there is no fixed `virtualenv` under the `packaging<26` cap; the advisory stays open. This is exactly the blocked state.

**C. Drop `cyclonedx-bom` from dev deps entirely (remove the SBOM generator).** Rejected — it would gut the Slice-7 reproducible-SBOM capability to dodge a dev-tool advisory. Disproportionate.

## The how (decided design)

### 1. Dependency bump + re-lock (`pyproject.toml`, `requirements-dev.txt`)
- Lift the `cyclonedx-bom` cap in `pyproject.toml`'s dev extra to admit 9.x (pin `>=9.0,<10.0`, the latest major), and add a `virtualenv>=21.14.9` floor.
- Re-lock: `./.venv/bin/pip-compile --extra=dev --output-file=requirements-dev.txt --strip-extras pyproject.toml` (+ `--upgrade-package` as needed). `pip install` the new dev set into `.venv`.
- **TDD guard:** a hermetic test that `requirements-dev.txt` pins `virtualenv ≥ 21.14.9` — RED today (21.14.5), GREEN after the re-lock. This locks the fix against a silent future revert.
- Verify: `requirements.txt` byte-identical (`git diff --exit-code requirements.txt`); `pip-audit` on the dev set no longer lists the `virtualenv` advisory.

### 2. Re-attest the release SBOM (`sbom/release-sbom.cdx.json`, `sbom/sbom.manifest.json`)
- Regenerate both committed artifacts with the now-installed `cyclonedx-bom 9.x` via the existing `make sbom-release` target (the `supply_chain/sbom.py` path), and commit them.
- Verify the existing `tests/test_sbom.py` gate is green under 9.x: reproducible (byte-identical across runs), well-formed CycloneDX, covers every pinned runtime dep (still 24), manifest digest + component_count consistent with the committed file.
- **Offline re-verify:** confirm `cyclonedx-py` 9.x generation makes no network calls (the posture invariant).

### 3. Sign-off update (`security-controls/supply-chain/sbom.md`)
- Flip the `pip-audit` / `virtualenv` item from blocked `[~]` → `[x]` with the actual locked version; note the release SBOM was re-attested with `cyclonedx-bom 9.x` (and the correct fix version is **21.14.9**). The D1 digest-scope note stays as-is.

## Decisions

- **Which `cyclonedx-bom`?** Latest major **9.x** (`>=9.0,<10.0`) — the clean, reviewed bump; 9.0.0 already satisfies the `packaging` math. *No alternative worth a gate.*
- **Force re-attestation even if the projection digest is unchanged?** **Yes** — regenerate regardless, so the committed SBOM's embedded tool/provenance metadata reflects the generator actually in the lock. A stale committed artifact that the drift gate happens not to catch is a provenance lie; honesty over the gate's silence.

## What's left to the builder
Exact pin edits (read the current caps at execute time), the re-lock's transitive churn (dev-only), and the regenerated SBOM's exact bytes/digest — all determined once the above is fixed.
