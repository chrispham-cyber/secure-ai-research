# SBOM & Supply-Chain Controls

> **Scope: PUBLIC / synthetic data only.**

Maps to **NIST SR** (Supply Chain Risk Management) and **SA** (System and Services
Acquisition). The goal: know exactly what the system is built from, and verify it before
use.

## Software Bill of Materials (SBOM)

Two SBOMs, for two jobs:

**Release SBOM — pinned, committed, gated.**

```bash
make sbom-release    # cyclonedx-py requirements --output-reproducible, from requirements.txt
#   -> sbom/release-sbom.cdx.json   (the reproducible release bill of materials)
#   -> sbom/sbom.manifest.json      (SHA-256 pin over a canonical {name,version,purl} set)
```

Built from the pinned **runtime** lock `requirements.txt` with `--output-reproducible` (no
`timestamp`/`serialNumber`, byte-identical across runs). Both files are **committed**. A hermetic
test (`tests/test_sbom.py`) regenerates from the lock and fails CI if the digest, the manifest,
or the completeness check drifts — **a dependency change that is not re-attested (`make
sbom-release` + commit) turns CI red.** This committed SHA-256 pin is the in-posture "signed
SBOM" (a cryptographic signature is *Future work*, below).

**Environment SBOM — dev convenience.**

```bash
make sbom            # cyclonedx-py environment -> sbom.json (current virtualenv, dev tools incl.)
```

`sbom.json` is **git-ignored**, non-reproducible, and includes dev tooling — a quick local
inventory, never the release artifact. CI regenerates the release SBOM on every run and uploads
`sbom/` as a build artifact (`.github/workflows/ci.yml`).

## Dependency integrity

- **Pinned, compiled locks.** `requirements.txt` / `requirements-dev.txt` are the pinned
  source of truth (pip-tools / `pip-compile`). `pyproject.toml` declares the top-level
  ranges; the lock is what CI, pip-audit, the SBOM, and Dependabot all read.
- **Known-vulnerability scan.** `pip-audit` runs in CI (advisory, non-gating) against the
  pinned set.
- **Automated updates.** Dependabot proposes dependency bumps (`.github/dependabot.yml`);
  review every lockfile diff before merging.

## Secret hygiene

- `gitleaks` and `detect-private-key` run in **pre-commit** and **CI**.
- `.gitignore` blocks `.env`, `.env.*`, `*.key`, `*.pem`, and `secrets/`.
- `env.example` holds only safe local-dev placeholders.

## Model supply chain

Models are dependencies too. Each approved model is pinned by **SHA-256** in the registry
and verified before use — a missing or mismatched hash fails loudly. See
[model runtime](../../infrastructure/model-runtime/models.md) and the
[verifier](../../src/secure_ai_research/ai_security/model_integrity/verify_model.py).

## Release sign-off (per release)

Re-run and re-date this gate for every release. The SBOM / manifest / completeness items are
machine-enforced by `tests/test_sbom.py`; the rest are a human review. Each line records what was
actually verified — no box is checked on trust.

### v0.1.0 — signed off 2026-11-20

- [x] `requirements.txt` (runtime lock) reviewed; the release SBOM is built from it.
- [x] Reproducible release SBOM produced (`make sbom-release`), **24 components**, SHA-256-pinned
  in `sbom/sbom.manifest.json`; drift + completeness gate green in CI.
- [x] Container base images pinned to specific tags (`pgvector/pgvector:pg16`,
  `minio/minio:RELEASE.2024-01-16T16-07-38Z`, `ollama/ollama:0.3.6`,
  `quay.io/keycloak/keycloak:26.0`, `otel/opentelemetry-collector-contrib:0.104.0`). Tag-pinned,
  not yet digest-pinned — digest pinning is a hardening item.
- [~] `pip-audit` reviewed: the **runtime** set (the release SBOM) carries no advisory. The dev
  tool `virtualenv==21.14.5` (requirements-dev.txt, via pre-commit — **not** in the release SBOM)
  has open advisories fixed in ≥ 21.14.10; bump via Dependabot. No runtime exposure.
- [~] Model integrity: the SHA-256 verifier is tested (`tests/test_verify_model.py`), but this
  scaffold ships **no real weights** (PUBLIC / synthetic) — N/A for v0.1.0, enforced once a model
  is pinned.
- [ ] `gitleaks`: runs in pre-commit and CI (`.github/workflows/ci.yml`); not re-run by hand for
  this sign-off — CI is the gate of record.

## Future work

Cryptographic SBOM signing (cosign / sigstore, or a detached GPG signature) is **out of the
current offline/deterministic posture** — it needs a network transparency log or a managed key.
The committed SHA-256 manifest is the in-posture integrity pin until then. Container **digest**
pinning (above) is the other open hardening item.

These controls address supply-chain tampering and secret exposure (threats T17/T18 in the
[threat model](../../architecture/threat-model.md)).
