# SBOM Guide

> _Scope: PUBLIC / synthetic data only._

## What and where
A **CycloneDX** Software Bill of Materials inventories every dependency and version. There are
two, for two jobs:

```bash
make sbom-release   # the release SBOM: reproducible, from the pinned lock, committed + gated
make sbom           # dev convenience: the current virtualenv, git-ignored, non-reproducible
```

- **`make sbom-release`** builds `sbom/release-sbom.cdx.json` from the pinned runtime lock
  `requirements.txt` (`cyclonedx-py requirements --output-reproducible`) and writes
  `sbom/sbom.manifest.json`, a **SHA-256 pin** over a canonical `{name, version, purl}`
  projection. Both are **committed**. `tests/test_sbom.py` regenerates from the lock and fails CI
  if the digest, the manifest, or the completeness check drifts — so a dependency change that is
  not re-attested (`make sbom-release` + commit) turns CI red. Run it whenever the runtime lock
  changes.
- **`make sbom`** writes `sbom.json` for the *current* environment; it is **git-ignored** (a
  throwaway inventory, dev tools included), never the release artifact.

CI regenerates the release SBOM on every run and uploads `sbom/` as a build artifact.

## How to read it
- `components[]` — each dependency: `name`, `version`, `purl`, `licenses`.
- Diff two SBOMs across releases to see exactly what changed.
- Cross-check against the `pip-audit` report for known vulnerabilities.

## In the assurance package (Phase 5)
Attach the release SBOM as evidence for the **SR** (supply chain) controls in the
[SSP](../system-security-plan/system-security-plan.md), and record it in the
[control-evidence matrix](../assessment-evidence/control-evidence-matrix.md). Full
supply-chain stance and the per-release checklist:
[security-controls/supply-chain/sbom.md](../../security-controls/supply-chain/sbom.md).
