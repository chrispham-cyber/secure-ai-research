# Security Policy

> **Scope: PUBLIC / synthetic data only.** This repository is a personal
> learning-and-research scaffold. It is **not** approved for CUI, classified, or otherwise
> controlled information, and makes **no** claim of ATO, CMMC, or accreditation. Do not
> store controlled data, real credentials, secrets, or model weights in this repository or
> its services.

## Data posture

- **Public / synthetic inputs only.** Threat data comes from public sources (NVD, CISA
  KEV, MITRE ATT&CK, Sigma) or synthetic fixtures clearly labeled as such.
- **No secrets, data, or weights in git.** `.gitignore` blocks `.env`, `.env.*`,
  `data/`, `models/`, `audit/`, `*.key`, `*.pem`, and `secrets/`. `env.example` contains
  only safe local-dev placeholders.
- **Classification separation.** Higher classifications would run as separate,
  non-communicating deployments — no shared database, endpoint, or credential. See
  [architecture/trust-boundaries.md](architecture/trust-boundaries.md).

## Supply-chain stance

- **Pinned dependencies.** `requirements.txt` / `requirements-dev.txt` are the compiled,
  pinned source of truth (pip-tools). `pyproject.toml` declares the top-level ranges.
- **Known-vuln scanning.** `pip-audit` runs in CI (advisory).
- **SBOM.** A CycloneDX SBOM is generated in CI and via `make sbom` — see
  [security-controls/supply-chain/sbom.md](security-controls/supply-chain/sbom.md).
- **Secret scanning.** `gitleaks` and `detect-private-key` run in pre-commit and CI.
- **Dependency updates.** Dependabot proposes updates (`.github/dependabot.yml`).
- **Model integrity.** Models are verified against a pinned SHA-256 in the registry before
  use ([verifier](src/secure_ai_research/ai_security/model_integrity/verify_model.py)); a
  missing or mismatched hash fails loudly.

## Application security

The platform's own controls — authorization-before-retrieval, permission checks outside
the LLM, append-only audit, and the handling of retrieved text as untrusted data — are
analyzed in the STRIDE [threat model](architecture/threat-model.md).

## Reporting a vulnerability

This is a personal, non-production project with no bug-bounty program. If you find a
security issue in this scaffold:

1. **Do not** open a public issue that includes a working exploit, secret, or real data.
2. Open a GitHub issue using the **security-finding** template with a clear description,
   affected files, and reproduction steps (sanitized), **or** contact the maintainer
   privately.
3. Expect a best-effort response; there is no SLA.

When in doubt, describe the *class* of problem rather than a step-by-step exploit.

## Supported versions

Pre-1.0: only the latest commit on the default branch is "supported." See
[CHANGELOG.md](CHANGELOG.md).
