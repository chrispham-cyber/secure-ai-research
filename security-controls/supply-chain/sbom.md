# SBOM & Supply-Chain Controls

> **Scope: PUBLIC / synthetic data only.**

Maps to **NIST SR** (Supply Chain Risk Management) and **SA** (System and Services
Acquisition). The goal: know exactly what the system is built from, and verify it before
use.

## Software Bill of Materials (SBOM)

A **CycloneDX** SBOM inventories every installed dependency and its version.

```bash
make sbom            # writes sbom.json for the current environment
#   runs scripts/gen-sbom.sh -> cyclonedx-py environment -o sbom.json
```

CI generates the same SBOM on every run and uploads it as a build artifact
(`.github/workflows/ci.yml`). `sbom.json` is git-ignored — it's a build output, regenerated
on demand, not a committed file.

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

## Checklist (per release)

- [ ] `requirements*.txt` recompiled and reviewed; lockfile diff understood
- [ ] `pip-audit` reviewed; no unaddressed high-severity advisory
- [ ] `make sbom` produced and archived with the release
- [ ] `gitleaks` clean on the full history for the release range
- [ ] Every model in the registry has a recorded, verified `sha256`
- [ ] Container base images pinned to a specific tag/digest

These controls address supply-chain tampering and secret exposure (threats T17/T18 in the
[threat model](../../architecture/threat-model.md)).
