# Supply-Chain Hardening Follow-up — Design

**Status:** awaiting approval (the one per-slice gate)
**Date:** 2026-11-20
**Branch (planned):** `hardening-supplychain-followup` off `main@12d0b01`
**Relation to the batch:** a *post-batch* follow-up, not part of the completed 8-slice Phase-5 batch. Closes the four supply-chain items logged against Slice 7 (2 deferred minors + 2 named Future-work), which Chris elected to "do all".

---

## Intent / why

Slice 7 shipped the reproducible, SHA-256-pinned release SBOM and an honest v0.1.0 sign-off that **named** its own gaps. This follow-up closes the four it named, so the sign-off has no open `[~]`/hardening items that are actually actionable in-posture. No new runtime behaviour; this is integrity-of-the-build work.

## Goals

1. **Minor 1 — direct-reference completeness.** `pinned_requirements` must count PEP 508 direct references (`name @ url`) and editable/VCS (`-e …#egg=name`) lines, so the SBOM completeness check can't silently under-count if the lock ever gains one. (Latent today — the lock is 100% `==`.)
2. **Minor 2 — digest scope, resolved honestly.** Decide and *document* what the manifest digest does and does not cover (see Decision D1).
3. **Future-work — container digest pinning.** Pin every resolvable compose base image to `tag@sha256:…`; the one unresolvable image (MinIO, retired upstream) stays tag-only with an inline reason.
4. **Future-work — virtualenv bump.** Re-lock `virtualenv` to ≥ 21.14.10 (the PYSEC-2026 fix) in `requirements-dev.txt`.

## Non-goals / anti-goals

- **No cryptographic SBOM signing (cosign/sigstore).** Out of the offline/deterministic posture (needs a transparency log or managed key); explicitly *not* in the scope Chris picked. Stays Future work.
- **No change to the release SBOM or its manifest.** virtualenv is dev-only (not in `requirements.txt`), so the committed `sbom/` artifacts and the `tests/test_sbom.py` drift gate must stay byte-identical and green. A diff there is a failure of this slice.
- **No runtime-path change.** `docker-compose.yml` is dev/integration infra; none of these images are on the default or hermetic path. No `src/…/{authz,research_service}.py` edits.
- **Don't widen the digest into volatile fields** (see D1) — that would make the drift gate flap on benign tool output.

## Constraints

- Deterministic/offline default; network only for the two Future-work items (digest resolution via `docker manifest inspect`; `pip-compile` against PyPI), both dev-time.
- Hermetic suite stays green: **461 + any new tests**, `-m "not integration"`.
- Gates kept: TDD + opus-xhigh whole-branch review + merge-to-main-local, then **push to the new `origin`** (private, already created this session).

## Approaches considered

**A. Close all four as one small follow-up slice (chosen).** One branch, four focused commits, one review. They share a theme (supply-chain integrity) and a sign-off document, so one reviewer pass covers them coherently. Matches every prior slice's shape.

**B. Only the two in-posture minors; defer the network Future-work again.** Rejected — Chris explicitly chose "Minors + Future-work", and the network items are now proven feasible (4/5 digests resolve; pip-compile works).

**C. One commit for everything.** Rejected — mixes a parser change, a docs ruling, an infra change, and a lockfile re-compile; harder to review and to revert independently.

## The how (decided design)

### 1. Minor 1 — direct-reference parsing (`supply_chain/sbom.py`, TDD)
Extend `pinned_requirements` so a spec line is recognised when it is either `name==version` (today) **or** `name @ url` (PEP 508 direct reference) **or** `-e …#egg=name` / `… #egg=name` (editable/VCS). Extract the distribution name, normalize (existing `_normalize`), add to the set. Blank/comment/`-r`/`-c`/`--hash`/marker handling unchanged. New tests: a `name @ https://…` line and an `-e git+https://…#egg=foo` line both appear in the result; the all-`==` path stays byte-identical.

### 2. Minor 2 — digest scope (Decision D1 — doc + comment only, no code change by default)
Resolve as a **ruling**: the manifest digest covers the `{name,version,purl}` projection *by design* — it is a dependency-**drift** gate, and git already provides whole-file integrity for the committed `sbom/` files. State this precisely in `security-controls/supply-chain/sbom.md` and a one-line comment at `sbom_digest`. (Alternative in D1 if Chris prefers coverage over simplicity.)

### 3. Future-work — container digest pinning (`docker-compose.yml`)
Rewrite 4 image lines to `name:tag@sha256:<digest>` (tag kept for human readability, digest is what Docker enforces). Resolve digests with `docker manifest inspect <ref>` at design/execute time. MinIO line keeps `minio/minio:RELEASE.2024-01-16T16-07-38Z` + a comment: *"digest-pin blocked: image retired from public registries (see Slice 3); tag-pinned only."* Optional enforcing guard — Decision D2.
Update the sign-off checklist: base-images item from "tag-pinned, not yet digest-pinned" → "4/5 digest-pinned; MinIO tag-only (retired)".

### 4. Future-work — virtualenv bump (`requirements-dev.txt`)
`./.venv/bin/pip-compile --extra=dev --output-file=requirements-dev.txt --strip-extras --upgrade-package virtualenv pyproject.toml` (the exact command in the lock's autogenerated header, plus `--upgrade-package virtualenv`). Confirm the new pin is ≥ 21.14.10 and that `requirements.txt`, `sbom/release-sbom.cdx.json`, `sbom/sbom.manifest.json` are **unchanged** (`git diff --exit-code` on those three). Update the sign-off `pip-audit` item `[~]`→`[x]` with the new version. Run `pip-audit` on the dev set to confirm the advisory clears.

## Decisions for Chris (the gate)

- **D1 — Minor 2 (digest scope).** *Recommend:* document the deliberate dependency-drift scope and leave the digest as-is (git covers whole-file integrity; widening into `license`/`externalReferences` would make the gate flap). *Alternative:* also store a second SHA-256 over the raw canonical SBOM bytes for whole-file tamper-evidence. — **Recommend: document-only.**
- **D2 — digest-pin enforcement.** *Recommend:* add a tiny hermetic test asserting every `image:` line in `docker-compose.yml` is either `@sha256:`-pinned or on a one-entry allowlist (MinIO), so a future un-pinned image reddens CI — matches the project's "gate it" ethos. *Alternative:* just pin, no test. — **Recommend: add the guard.**

## What's left to the builder
Exact digests (resolved at execute time), the precise parser branch structure, and test names — all idiomatic once the above is fixed.
