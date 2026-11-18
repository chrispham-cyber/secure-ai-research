# SBOM Guide

> _Scope: PUBLIC / synthetic data only._

## What and where
A **CycloneDX** Software Bill of Materials inventories every installed dependency and
version. Generate it with:

```bash
make sbom      # writes sbom.json for the current environment
```

CI produces the same `sbom.json` on every run and uploads it as a build artifact.
`sbom.json` is **git-ignored** — it is a build output, regenerated on demand, archived with
each release rather than committed.

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
