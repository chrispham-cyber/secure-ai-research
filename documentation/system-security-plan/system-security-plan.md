# System Security Plan — TEMPLATE

> _Scope: PUBLIC / synthetic data only. This is an unfilled template; it is not an
> authorization package and claims no ATO/CMMC._

> Fill each section in Phase 5 (week 19). Prompts in _italics_ say what belongs there;
> delete them as you write.

## 1. System identification
- **Name / version:** _…_
- **Owner / author:** _…_   **Date:** _…_
- **Purpose:** _one paragraph — what the system does and for whom._

## 2. System environment & boundary
- **Components:** _enumerate the processes and data stores (reuse the DFD in
  [architecture/data-flow.md](../../architecture/data-flow.md))._
- **Authorization boundary:** _what is inside vs. outside; interconnections._
- **Data types & classification:** _PUBLIC / synthetic only in this deployment._

## 3. Control implementation
For each family, state **how** it is implemented here and **status** (planned / partial /
met). Reference the control doc under [`security-controls/`](../../security-controls/).

| Family | Implementation in this system | Status |
|--------|-------------------------------|--------|
| **AC** Access Control | _RBAC/ABAC, authorize-before-retrieve, roles._ | _…_ |
| **AU** Audit & Accountability | _Append-only research records._ | _…_ |
| **CM** Configuration Management | _Pinned deps, IaC, pre-commit._ | _…_ |
| **IA** Identification & Authentication | _Keycloak/OIDC (Phase 5)._ | _…_ |
| **SC** System & Communications Protection | _Loopback binding, encryption._ | _…_ |
| **SI** System & Information Integrity | _Schema validation, model verifier._ | _…_ |
| **SR** Supply Chain | _SBOM, pip-audit, model-hash pinning._ | _…_ |
| **IR** Incident Response | _Runbook under security-controls/._ | _…_ |

## 4. Risk summary
_Link to the [risk register](../risk-assessment/risk-register.md); summarize top risks and
their treatment._

## 5. Roles & responsibilities
_Who owns operation, security, and acceptance (see
[roles.md](../../infrastructure/identity/roles.md))._

## 6. Continuous monitoring
_What is monitored, how often reviewed, re-assessment triggers (see the threat model's
re-review triggers)._
