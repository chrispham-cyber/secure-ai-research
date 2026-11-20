# System Security Plan (SSP)

> Scope: PUBLIC / synthetic data only. This is a design-assurance SSP for a single-tenant,
> loopback-bound research platform. It is **not** an authorization package and claims **no
> ATO / CMMC / baseline completeness** — it documents the controls the platform actually
> implements and their honest status.

## 1. System identification
- **Name / version:** Secure AI Research Platform (SAIR) — Phase 5 (Slices 1a–6), 2026-11-20.
- **Owner / author:** Chris Pham (with Claude).   **Date:** 2026-11-20.
- **Purpose:** An evidence-grounded AI assistant for cybersecurity research. It ingests PUBLIC
  threat-intelligence sources (NVD, MITRE ATT&CK, CISA KEV, SigmaHQ), retrieves under an
  access-control gate, and produces cited reports. It is built securely as its primary goal:
  deterministic and offline by default, with real infrastructure (OIDC, pgvector, object store,
  local LLM) behind opt-in Protocol seams.

## 2. System environment & boundary
- **Components (see [data-flow.md](../../architecture/data-flow.md)):** processes **P1** ingestion,
  **P2** chunk/embed, **P3** authorize, **P4** retrieve, **P5** inference, **P6** report, **P7**
  audit; data stores **D1** object store, **D2** pgvector DB, **D3** model registry, **D4** audit
  log. External entities: Analyst, PUBLIC feeds, Reviewer.
- **Authorization boundary (see [trust-boundaries.md](../../architecture/trust-boundaries.md)):**
  the FastAPI application and its local stores. Everything runs single-tenant and bound to
  `127.0.0.1`. Optional backends (Keycloak, pgvector, MinIO, Ollama) sit behind seams and are off
  by default; when enabled they are the nearest external interconnections and are covered by the
  SC controls below.
- **Data types & classification:** PUBLIC / synthetic only. No CUI or classified data; a spill of
  controlled data is prevented by lane separation, not by this deployment.

## 3. Control implementation
For each family: **how** it is implemented here and its **status** (met / partial / planned). Each
row links the control set under [`security-controls/`](../../security-controls/) and the code.
Evidence (file + test) is enumerated in the
[control→evidence matrix](../assessment-evidence/control-evidence-matrix.md), which CI enforces.

| Family | Implementation in this system | Status |
|--------|-------------------------------|--------|
| **AC** Access Control | RBAC + a within-PUBLIC sensitivity (ABAC) tier; `authorize()` runs **before** any retrieval; deny-by-default. `src/secure_ai_research/retrieval/authz.py`. | met |
| **AU** Audit & Accountability | Tamper-evident signed audit chain (SHA-256 hash-chain + HMAC envelope); one record per request path; `verify_chain` detects edit/reorder/forgery. `src/secure_ai_research/audit/`. | met |
| **CM** Configuration Management | Pinned dependencies, pre-commit hooks (gitleaks, detect-private-key, ruff, black), and a CI suite that runs the full battery incl. the evidence-matrix gate. `.github/workflows/ci.yml`. | partial |
| **IA** Identification & Authentication | Signed-token (OIDC/JWT) identity retires the dev `X-Role` header in prod; a fail-closed secret gate refuses boot on weak/placeholder secrets. `src/secure_ai_research/identity/`, `.../secret/`. | met |
| **SC** System & Communications Protection | Loopback-only binding; in-transit posture gate (TLS-enforcing `sslmode` allowlist, MinIO-secure flag); at-rest Cipher seam (opt-in Fernet); agent call-budget rate limiter. `src/secure_ai_research/transit.py`, `.../crypto/`, `.../agents/rate_limit.py`. | partial |
| **SI** System & Information Integrity | Pydantic schema validation; retrieved text treated as untrusted data; prompt-injection corpus + pipeline-safety harness; SHA-256 model-integrity verifier; citation/grounding faithfulness gates. `src/secure_ai_research/ai_security/`, `.../evaluation/`. | met |
| **SR** Supply Chain | Reproducible release SBOM (`cyclonedx-py`), SHA-256-pinned in a committed manifest and **signed** with a keyed, offline cosign signature verified in CI against the committed public key (no transparency log, no `id-token`); `pip-audit` + Dependabot + pinned lockfile. `security-controls/supply-chain/`. | met |
| **IR** Incident Response | Incident-response runbook under the security-controls set; present but not yet exercised. `security-controls/incident-response/`. | partial |

## 4. Risk summary
See the [risk register](../risk-assessment/risk-register.md), seeded from the STRIDE
[threat model](../../architecture/threat-model.md) (T1–T19). The top residual risks are
unauthorized retrieval across the confidentiality boundary (T2/T6/T15) and prompt injection via
retrieved content (T4/T9), both mitigated by authorize-before-retrieve plus the disclosure and
injection test suites. Role spoofing (T1/T7), the top Phase-1 risk, is now mitigated by the
signed-token identity shipped in Slice 4. One residual is accepted: the opt-in live-fetch timing
side-channel (senior-analyst-only), triaged in Phase 3/5 as Minor.

## 5. Roles & responsibilities
Roles and their permissions are defined in
[roles.md](../../infrastructure/identity/roles.md) and enforced in `retrieval/authz.py`. In this
single-developer deployment the owner holds operation, security, and acceptance; a shared
deployment would separate the security and acceptance roles and provision real identities in
Keycloak.

## 6. Continuous monitoring
The CI suite (`.github/workflows/ci.yml`) runs the full test battery on every change, including
the evidence-matrix gate that fails if any cited control artifact moves. The threat model is a
living document: re-assess on any of its re-review triggers — a new data classification, a new
external feed or integration, a change to the auth/authz model, a move off the local model
runtime, a change to the audit store's integrity guarantees, or any exposure beyond loopback.
