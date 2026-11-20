# SBOM Signing (keyed, offline cosign) — Design

**Date:** 2026-11-20
**Status:** Approach approved by Chris ("keyed offline cosign"); awaiting design "go" before planning.
**Slice:** Supply-chain follow-up #1 of 2 (the other, done after this: model-behavior eval).
**Repo:** `/Users/fox/Chris/CyberBase/secure-ai-research` (private remote `github.com/chrispham-cyber/secure-ai-research`). Branch `sbom-cosign-signing` off `main@2c3838c`.

## Intent & why
The release SBOM (`sbom/release-sbom.cdx.json`) is reproducible and dependency-drift-gated, but it carries **no cryptographic signature**, and the integrity manifest (`sbom/sbom.manifest.json`) pins only the dependency *projection* (`{name,version,purl}` SHA-256), not the whole file. Slice 7 named "real cryptographic SBOM signing (cosign/sigstore)" as Future work and rejected it then because it "needs a network transparency log or a managed key" (`security-controls/supply-chain/sbom.md:102-108`).

This slice supersedes that rejection with the one option that keeps the platform's offline/deterministic posture: **keyed `cosign sign-blob --tlog-upload=false`** over the whole SBOM file bytes, verified offline against a committed public key, with no transparency log and no network. It also closes the whole-file tamper-evidence gap the manifest digest leaves open (`sbom.md:33-34`).

## Goals
- A detached signature over the committed SBOM **file bytes**, offline-verifiable with a committed public key (`sbom/cosign.pub`) — no Rekor, no network, no OIDC.
- Reproducible local signing (`make sbom-sign`) by the key-holder; always-on CI **verification** of the committed signature using the **public key only** (no secret, no `id-token` in CI).
- The default `-m "not integration"` suite stays offline/stdlib and never requires `cosign` installed or network.
- A gate that catches a **stale signature** (SBOM re-attested via `make sbom-release` but not re-signed).
- Honest docs: update the sign-off + SR-3 evidence + SSP + README + threat-model; document the keyed-vs-keyless tradeoff, the private-repo→public-Rekor identity-leak reasoning, and the key-management burden.

## Non-goals
- No keyless Fulcio/Rekor, no transparency log (documented as the deliberate posture choice; kept as Future work).
- No key-rotation automation (documented procedure only).
- Not signing the manifest or other files — the manifest's `sbom_sha256` is already tied to the SBOM by the hermetic drift gate (`tests/test_sbom.py::test_manifest_digest_matches_committed_sbom`), so a signed SBOM + that gate covers both.
- No SLSA provenance / build-attestation claims — this is a detached blob signature, described as exactly that.

## Anti-goals (failure even if it "works")
- Requiring `cosign` or network in the base CI pytest — breaks the offline default.
- A private signing key committed to the repo (`.gitignore` must keep blocking `*.key`/`*.pem`).
- A signature that goes stale silently on re-attest with nothing to catch it.
- Over-claiming the control's strength.

## Constraints
- `cosign` is a Go binary (no pip footprint). `supply_chain/signing.py` shells out via `subprocess`, mirroring `supply_chain/sbom.py`→`cyclonedx-py` and `compliance.evidence`→`pytest`. No new runtime or base dependency; importing the module pulls nothing heavy.
- Real sign/verify tests are `-m integration`, skip-clean when `cosign` is absent (mirror `tests/test_integration_minio.py::_require_minio`, `test_integration_ollama_eval._require_ollama`).
- Private key lives only locally / as a GitHub Actions secret; `sbom/cosign.pub` is committed. The signature `sbom/release-sbom.cdx.json.sig` is committed so a clean checkout verifies without re-signing.
- CI **verifies** (public key, no secret, no `id-token`); CI does **not** sign. Signing is a release act by the key-holder.

## Approaches considered
- **A — Keyed, offline cosign `sign-blob --tlog-upload=false` (CHOSEN).** Whole-file SBOM signature, committed `.sig` + `cosign.pub`, offline verify (`cosign verify-blob --insecure-ignore-tlog`). Closest to the offline/deterministic posture; recognizable supply-chain tooling; locally reproducible verification; no identity leak. Tradeoff: the key-holder (Chris) manages a private key + rotation.
- **B — GitHub-native attestation (`actions/attest-sbom`).** Rejected: CI-only, needs network + `id-token: write`, GitHub-platform-coupled, no offline/local verification. (For a private repo it would at least keep attestation off the public Rekor log — noted — but it fails the offline-verify goal.)
- **C — Keyless Sigstore (Fulcio/Rekor).** Rejected: publishes this **private** repo's CI identity to the **public** Rekor transparency log, CI-only, network-dependent — furthest from posture.
- **D — detached GPG/minisign.** Rejected: cosign is the recognizable supply-chain signing tool for the portfolio; GPG key/trust management is heavier, minisign is less industry-standard here.

## The how (decided)
### New module `src/secure_ai_research/supply_chain/signing.py` (stdlib-only, shells out)
- Constants: `_SBOM = "sbom/release-sbom.cdx.json"`, `_SIG = _SBOM + ".sig"`, `_PUB = "sbom/cosign.pub"`.
- `SigningError(RuntimeError)`.
- Pure, hermetically-testable command builders:
  - `sign_command(key_ref, sbom, sig) -> list[str]` → `["cosign","sign-blob","--key",key_ref,"--tlog-upload=false","--yes","--output-signature",sig,sbom]`.
  - `verify_command(pub, sig, sbom) -> list[str]` → `["cosign","verify-blob","--key",pub,"--insecure-ignore-tlog=true","--signature",sig,sbom]`.
- `cosign_available() -> bool` = `shutil.which("cosign") is not None`.
- `signing_artifacts_state(repo_root)`: which of `{.sig, cosign.pub}` exist and are non-empty — backs the all-or-nothing hermetic gate.
- `sign_release_sbom(repo_root, key_ref) -> None`: run `sign_command` (cwd=repo_root); non-zero exit / missing cosign → `SigningError`.
- `verify_release_sbom(repo_root) -> bool`: run `verify_command` over the committed trio; raise `SigningError` on failure. (Needs cosign ⇒ integration/CI-job only.)
- `__main__`: `sign_release_sbom(Path.cwd(), key_ref)` for `make sbom-sign` (key ref from `$COSIGN_KEY`/argv; `$COSIGN_PASSWORD` passed through env to cosign).

### Makefile
- `sbom-sign` (local; needs cosign + key): `./.venv/bin/python -m secure_ai_research.supply_chain.signing`.
- `sbom-verify` (local/CI; needs cosign): verify the committed trio via the module.
- Add both to `.PHONY` + `## help` comments.

### CI (`.github/workflows/ci.yml`)
- New job `sbom-verify` (separate from the hermetic `test` job), `permissions: contents: read` (NO `id-token`):
  - checkout@v7; install cosign via `sigstore/cosign-installer@<pinned tag>` (Dependabot-managed, like the other pinned actions);
  - **if `sbom/cosign.pub` + `sbom/release-sbom.cdx.json.sig` are present** → `cosign verify-blob --key sbom/cosign.pub --insecure-ignore-tlog=true --signature sbom/release-sbom.cdx.json.sig sbom/release-sbom.cdx.json` → **gating** (red on mismatch = stale/forged signature);
  - **if absent** → skip cleanly (CI stays green before the one-time key ceremony).
- The existing advisory SBOM-regenerate + upload step is unchanged.

### Tests
- Hermetic `tests/test_signing.py`: exact `sign_command`/`verify_command` strings (incl. `--tlog-upload=false` / `--insecure-ignore-tlog=true`); `cosign_available` reflects PATH (monkeypatch `shutil.which`); **all-or-nothing artifact gate** — if either of `{.sig, cosign.pub}` exists, both must (catches a half-done ceremony); the module imports no heavy dep.
- Integration `tests/test_integration_signing.py` (`pytestmark = integration`, skip-clean if `not cosign_available()`): generate a throwaway keypair in a tmpdir, sign the committed SBOM bytes → verify True; flip one byte → verify fails; and, **if a committed `.sig`+`.pub` exist**, verify the **committed** signature against the **committed** SBOM — the real stale-signature check, matching the CI `sbom-verify` job.

### Docs
- `security-controls/supply-chain/sbom.md`: revise the "in-posture signed SBOM = SHA-256 pin" wording (a real signature now exists); keep keyless/Rekor as documented Future work with the tradeoff; add a dated sign-off line; document key management (generate offline, commit pub, rotation = re-sign + commit new pub) + the private-repo/Rekor identity-leak reasoning.
- `documentation/sbom/sbom-guide.md`: add the sign + verify flow (incl. the cosign install).
- `documentation/assessment-evidence/control-evidence-matrix.md` SR-3: add signing evidence (integration verify test + the CI `sbom-verify` job + the hermetic artifact gate).
- `system-security-plan.md`: fix the stale "planned for Slice 7" SR line; add signing.
- `README.md`: note the signed, offline-verifiable SBOM.
- `architecture/threat-model.md` T17: add "signed SBOM (cosign, offline-verifiable)".
- `ROADMAP.md`: tick the signing line.

### No pip changes
No new pip dependency (cosign is a binary). Document the cosign install in the Makefile help + sbom-guide. No `[sign]` extra.

## What's left to the builder (and one decision for Chris)
- **Exact pinned `sigstore/cosign-installer` tag** — pick a real, ≥2-week-old tag at execution (Dependabot manages it thereafter).
- **Pure-helper signatures / test wording** follow the `sbom.py` / `test_sbom.py` precedent.
- **KEY-CEREMONY DECISION (Chris's).** A real committed signature + an always-gating CI verify need a one-time key ceremony that only the key-holder can do (and `cosign` is **not installed locally** — recon confirmed `which cosign` = not found):
  1. `cosign generate-key-pair` (offline) → keep `cosign.key` private (gitignored), set a password;
  2. commit `sbom/cosign.pub`;
  3. `make sbom-release` (if needed) then `make sbom-sign` → commit `sbom/release-sbom.cdx.json.sig`;
  4. (optional, only if a future release workflow signs in CI) add `COSIGN_PRIVATE_KEY` + `COSIGN_PASSWORD` as GitHub secrets.
  - **Default this slice ships:** the full infra (module, Makefile, hermetic + integration tests, CI verify job that **skips until signed**, docs) — all green — with the ceremony documented as a short one-time step. The CI verify job flips to **gating** automatically once `cosign.pub` + `.sig` are committed.
  - **Alternative:** Chris installs cosign + runs the ceremony during this slice; we commit a real `.sig` + `cosign.pub`, and the slice lands with CI verification gating-green end to end.

## Verification (how we'll know it's done)
- Hermetic suite green incl. `tests/test_signing.py`; `-m "not integration"` still needs no cosign/network.
- `tests/test_integration_signing.py` green against a real local cosign (or skip-clean if absent).
- CI `sbom-verify` job: green-skip pre-ceremony, gating-green post-ceremony.
- opus-xhigh whole-branch review = MERGE; merge-to-main-local + push; CI green on the private remote.
