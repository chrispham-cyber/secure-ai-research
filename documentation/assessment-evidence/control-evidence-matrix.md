# Control → Evidence Matrix — TEMPLATE

> _Scope: PUBLIC / synthetic data only. Unfilled template._

> Fill in Phase 5 (week 20). Each control claimed in the
> [SSP](../system-security-plan/system-security-plan.md) needs an artifact that evidences
> it — a file, a test, a CI run, a config. "Implemented" without evidence is a claim, not
> assurance.

| Control | Claim | Evidence artifact | Where | Verified by |
|---------|-------|-------------------|-------|-------------|
| AC-3 Access enforcement | Authorize-before-retrieve | `retrieval/authz` + disclosure test | `src/…/retrieval/`, `ai-security/information-disclosure/` | _test run_ |
| AU-3 Audit content | Research-record schema | Append-only JSONL emitter | `src/…/audit/record.py` | _unit test_ |
| SI-7 Software integrity | Model-hash verification | SHA-256 verifier + registry | `src/…/ai_security/model_integrity/` | _unit test_ |
| SR-3 Supply chain | SBOM + dependency scan | `sbom.json`, pip-audit log | CI artifacts | _CI run_ |
| SC-7 Boundary protection | Loopback-only exposure | `docker-compose.yml` port bindings | repo root | _config review_ |
| … | … | … | … | … |

## Guidance
_Prefer evidence that re-generates (a test, a CI job) over a static screenshot. Link the
exact file or run. For each row, note the date verified and who verified it._
