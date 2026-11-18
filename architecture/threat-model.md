# Threat Model (STRIDE)

> **Scope: PUBLIC / synthetic data only.** This repository runs in the PUBLIC lane and
> handles no CUI or classified data. This model analyzes the platform's *intended*
> Phase-2 design so the controls can be reviewed before the retrieval/inference code
> lands; where a mitigation is not yet implemented, it names the roadmap phase that
> builds it.

**Method:** STRIDE per element, over the data-flow diagram in
[data-flow.md](data-flow.md). **Date:** 2026-11-18. **Author:** Chris Pham (with Claude).
A threat model is a living document — re-run it on the re-review triggers at the end.

## 1. Scope & assumptions

**In scope:** the ingestion → retrieval → inference → report path, its data stores, the
audit trail, the model-integrity control, and the local-dev supply chain / CI.

**Out of scope:** multi-lane (CUI/classified) deployment (see
[trust-boundaries.md](trust-boundaries.md)); hardening of third-party images beyond
pinning; physical security of the host.

**Assumptions (if wrong, re-model):**
- Single-tenant, single developer host; services bound to loopback (`docker-compose.yml`).
- Data is public/synthetic; a *spill* of controlled data is prevented by the lane
  separation, not by this model.
- Phase 1 authenticates role via a trusted-only header stub (`X-Role`); real identity
  (Keycloak/OIDC) is Phase 5. **A self-asserted header is not an authentication control
  outside local dev.**

## 2. System overview

- **Actors / assets an attacker wants:** the integrity of the knowledge corpus (poisoning
  changes every answer), the confidentiality boundary between roles, the local model
  (swap = controlled output), and the audit trail (erase = deniability).
- **Components & data stores** are numbered in [data-flow.md](data-flow.md): external
  entities (Analyst, Public feeds, Reviewer); processes **P1** ingestion, **P2**
  chunk/embed, **P3** authorize, **P4** retrieve, **P5** inference, **P6** report, **P7**
  audit; stores **D1** object store, **D2** pgvector DB, **D3** model registry, **D4**
  audit log.

## 3. Risk scale

Risk = Likelihood (1–3) × Impact (1–3): **Low** (1–2), **Medium** (3–4), **High** (6),
**Critical** (9). "Existing control" is what ships today; "Mitigation" names the control
or the roadmap phase that completes it.

## 4. Threat table

| ID | Element | STRIDE | Threat | L | I | Risk | Existing control | Mitigation (→ phase if not yet built) |
|----|---------|--------|--------|---|---|------|------------------|----------------------------------------|
| T1 | Analyst → P3 | **S** | Caller asserts a role they do not hold (Phase-1 `X-Role` header). | 3 | 2 | High | Header stub documented as dev-only | Keycloak/OIDC auth → Phase 5; authz-before-retrieval bounds blast radius |
| T2 | P3/P4 | **E** | Caller retrieves documents above their role. | 2 | 3 | High | `authz` gate designed before retrieve | `authorize()` enforced before `retrieve()` + two-user access tests → Phase 2/3 |
| T3 | Feeds → P1 | **S/T** | A public feed is impersonated or tampered in transit → poisoned input. | 2 | 2 | Medium | — | TLS to source + pin `sha256:` content hash + source allowlist → Phase 2 |
| T4 | P1 / D2 | **T** | Malicious document content poisons the corpus (stored prompt injection / data poisoning). | 2 | 3 | High | Schema **PUBLIC-only** validation; stubs fail loud | Treat retrieved text as untrusted data; injection eval → Phase 4; integrity hash |
| T5 | P1 | **D** | Oversized / malformed feed exhausts ingestion. | 2 | 1 | Low | — | Bounded input size + timeouts → Phase 2 |
| T6 | P3 | **I** | Authorization bug leaks a document into the model's context. | 2 | 3 | High | authz-before-retrieval design; fail-loud stubs | `information-disclosure/` two-user eval → Phase 3; deny-by-default |
| T7 | P5 / agents | **E** | Confused deputy: the model requests data on behalf of a higher role. | 2 | 3 | High | Permission checks **outside** the LLM (`agents/functions`) | Role bound to request, never model-controlled → Phase 3 |
| T8 | P5 / D3 | **T** | Model swapped for a backdoored/altered one. | 1 | 3 | Medium | **SHA-256 verifier + registry (real)** | `verify_model` before use; fail loud on missing/mismatched hash |
| T9 | P5 | **I** | Prompt injection in retrieved text exfiltrates context or drives a tool call. | 2 | 3 | High | Permission checks outside LLM | authz-before-retrieval (nothing unauthorized in context); retrieved text = data; injection suite → Phase 4 |
| T10 | P5 | **D** | Unbounded generation / huge context exhausts the host. | 2 | 1 | Low | Local Ollama (no per-token cost) | Context + output limits → Phase 2 |
| T11 | P6 | **I/R** | Report presents uncited/hallucinated claims as fact. | 2 | 2 | Medium | Design: drop uncited claims | Every claim cites a doc id; human review before acceptance → Phase 2 |
| T12 | P7 / D4 | **R** | Analyst denies an analysis, or a record is never written. | 2 | 2 | Medium | **Append-only JSONL audit emitter (real)** | Emit on every analysis; WORM/signing → Phase 5 |
| T13 | D4 | **T** | Audit log edited to hide an action. | 1 | 3 | Medium | Append-only writes | Restrictive FS perms; hash-chain / WORM → Phase 5 |
| T14 | D1 | **I** | Raw payloads in object store read by an unauthorized party. | 1 | 2 | Low | Loopback-only port binding | Real credentials for shared deploy; encryption-at-rest (`security-controls/encryption`) |
| T15 | D2 | **T/I** | Direct DB access bypasses the authz gate. | 2 | 3 | High | DB bound to loopback | App-mediated access only; least-privilege DB roles → Phase 2/5 |
| T16 | D3 | **T** | Registry edited to point at a malicious model or blank a hash. | 1 | 3 | Medium | Version-controlled + code review; verifier fails loud on null hash | Signed registry / approval workflow → Phase 5 |
| T17 | Supply chain / CI | **T** | Compromised dependency or CI step injects code. | 2 | 3 | High | **Pinned reqs, pip-audit, CycloneDX SBOM, Dependabot** | Keep pins current; review lockfile diffs; `security-controls/supply-chain` |
| T18 | Repo / CI | **S** | A committed secret enables impersonation of a service. | 2 | 3 | High | **gitleaks + detect-private-key pre-commit + `.gitignore`** | Secret scanning in CI; no secrets in `env.example` |
| T19 | Network | **D/I** | A published service is reachable from the LAN and abused. | 1 | 2 | Low | **All ports bound to `127.0.0.1`** | Auth + network controls before any `0.0.0.0` exposure |

Every STRIDE category is exercised: **S** (T1, T3, T18), **T** (T3, T4, T8, T13–T17),
**R** (T11, T12, T13), **I** (T6, T9, T11, T14, T15, T19), **D** (T5, T10, T19),
**E** (T2, T7).

## 5. Top risks to fix first

1. **Unauthorized retrieval (T2, T6, T15).** The confidentiality boundary is the whole
   point of the platform. Fix order: enforce `authorize()` before `retrieve()`, keep the
   DB app-mediated and loopback-only, and ship the two-user disclosure test (Phase 2/3).
2. **Prompt injection via retrieved content (T4, T9).** Retrieved text is attacker-
   influenceable. Treat it as data, never instructions; authz-before-retrieval keeps
   unauthorized content out of context entirely; build the injection eval suite (Phase 4).
3. **Role spoofing in Phase 1 (T1, T7).** The header stub is dev-only. Do not deploy
   beyond localhost without real auth (Keycloak, Phase 5); keep permission checks outside
   the LLM so a convincing model request can't self-authorize.
4. **Supply-chain & secrets (T17, T18).** Already the strongest area (pinning, pip-audit,
   SBOM, gitleaks). Keep it green; review every lockfile change.
5. **Model integrity (T8, T16).** The real control. Never load a model whose hash isn't in
   the registry; a null/mismatched hash must fail loud, not warn.

## 6. AI-specific threats (roadmap §5)

| Threat | Why it's different for an AI system | Control in this repo |
|--------|-------------------------------------|----------------------|
| **Prompt injection** | Retrieved/user text can carry instructions the model may follow. | Retrieved text treated as data; authz-before-retrieval; injection eval (Phase 4); permission checks outside the LLM (T4, T9). |
| **Unauthorized retrieval / information disclosure** | A RAG system can leak any document it can reach into an answer. | Authorization applied **before** retrieval, never after generation; deny-by-default; two-user eval (T2, T6). |
| **Model & dataset integrity** | A swapped model or poisoned corpus silently changes every output. | SHA-256 model verifier + registry; `PUBLIC`-only schema + content hashes on documents (T4, T8, T16). |
| **Excessive agency** | An agent given tools can act beyond intent. | The model may *request* a function; the application decides — checks live outside the LLM; read-only tool stubs (T7). |

## 7. Open questions & re-review triggers

**Open questions:** final identity model (Keycloak realm/roles); whether the audit log
graduates to WORM/signed storage; retention policy for raw payloads in D1.

**Re-review when any of these change:** a new data classification enters the system; a new
external integration or feed is added; the authentication/authorization model changes; the
model runtime moves off local Ollama; the audit store or its integrity guarantees change;
a service is exposed beyond loopback.

**Suggested security tests:** two-user access-control test (T2/T6), prompt-injection corpus
eval (T4/T9), model-hash-mismatch fails loud (T8 — partially covered today), gitleaks on
every commit (T18 — covered). Pair with the `owasp-top10` review when the API grows.
