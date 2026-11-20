# Roles & Access Control

> **Scope: PUBLIC / synthetic data only.** All roles below operate in the PUBLIC lane.

Access is **role-based (RBAC)** with **attribute-based (ABAC)** refinement: a request is
permitted only if the role allows the action *and* the document's attributes
(classification, source sensitivity) permit it. In this repo classification is always
`PUBLIC`; the model is built so the same gate works when more lanes exist.

## The six roles

| Role | Can do | Cannot do |
|------|--------|-----------|
| **research_analyst** | Run analyses; retrieve the authorized corpus; produce **draft** reports. | Accept its own conclusions; change sources, models, or config; read audit logs. |
| **senior_analyst** | Everything an analyst can, plus **review and accept** conclusions; wider retrieval scope. | Administer identity or infrastructure. |
| **data_steward** | Manage sources and ingestion; set/attest document classification and provenance. | Run analyses with elevated scope; approve models. |
| **model_admin** | Manage the model registry; approve models (hash + provenance + license). | Read the corpus or run analyses by default. |
| **security_auditor** | **Read-only** access to audit logs, SBOMs, and control configuration. | Run analyses, retrieve documents, or change anything. |
| **administrator** | Infrastructure and identity administration (least-privilege, break-glass). | Silently bypass the audit trail. |

Separation of duties is deliberate: the analyst who drafts is not the reviewer who
accepts; the steward who classifies data is not the admin who approves models.

## Retrieval sensitivity tiers (ABAC)

Within the PUBLIC lane, every document carries a **sensitivity** attribute — `ROUTINE`
(the default) or `RESTRICTED`. This is the concrete form of `senior_analyst`'s "wider
retrieval scope":

- **ROUTINE** documents are retrievable by any role the allowlist grants retrieval
  (`research_analyst`, `senior_analyst`).
- **RESTRICTED** documents are retrievable **only** by `senior_analyst`.

`RESTRICTED` is a *privilege tier, not a handling class* — the document is still `PUBLIC`.
Enforcement is in the pre-retrieval `authorize` gate
([`retrieval/authz.py`](../../src/secure_ai_research/retrieval/authz.py)), so a `RESTRICTED`
document never enters a `research_analyst`'s retrieval scope on any path (id-route or
search), and an unauthorized request returns the same `NOT_FOUND` response as one for an
absent document (no response-level existence oracle). See the two-user information-
disclosure test
[`tests/test_access_control.py`](../../tests/test_access_control.py).

## Live fetch-on-miss is a senior-only capability

Opt-in live fetch-on-miss (`SAIR_ALLOW_LIVE_FETCH`, default **off**) lets the CVE id-route
answer a CVE absent from the packaged corpus by fetching it from NVD. It is restricted to
`senior_analyst`. Two reasons, one gate (`may_live_fetch` in
[`retrieval/authz.py`](../../src/secure_ai_research/retrieval/authz.py)):

- It does **network egress** and it **writes** the corpus (it indexes the fetched document),
  so it is a privileged, side-effecting action, not a read.
- Absent a role gate, *whether a fetch fires* would reveal whether a `RESTRICTED` document is
  present: an absent id triggers a fetch, a present-but-`RESTRICTED` id does not — a
  timing/egress existence oracle, even though the `NOT_FOUND` response itself is byte-identical.
  Gating fetch to a role for which `authorize` never withholds a PUBLIC document (no
  present-but-hidden class — today `senior_analyst`) collapses the two cases: for every other
  role an absent id and a present-but-`RESTRICTED` id are identical in response **and** in
  fetch behavior (both zero fetches). **Invariant:** widen the fetch-eligible set only in
  lockstep with any new sensitivity tier, or the oracle reopens.

## A model never inherits the analyst's privileges

When an analyst runs an analysis, the model and any agent tools operate under their **own
constrained permission set**, never the analyst's. Concretely:

- A tool call is authorized against the **caller's role**, by application code, *before*
  it runs — the model cannot grant itself access by requesting a function.
- The model only ever receives documents the caller is authorized to see (authorization is
  applied **before** retrieval). It has no standing credentials of its own.
- "The model may *request* a function; the application independently decides if it is
  permitted" — see [`agents/functions.py`](../../src/secure_ai_research/agents/functions.py).

This is the guard against **excessive agency** and **confused-deputy** escalation (threats
T7/T9 in the [threat model](../../architecture/threat-model.md)).

## Authentication: verified signed tokens (Slice 4)

The caller's role is resolved from a **verified signed token**, not a self-asserted header. The
`get_role` dependency ([`api/deps.py`](../../src/secure_ai_research/api/deps.py)) runs before every
`/research/*` handler and maps a credential failure to **401** (with `WWW-Authenticate: Bearer` and
a reason-free body — no auth-failure oracle) and an unavailable identity backend to **503** (fail
closed). Both are boundary rejections: they write **zero** audit records (the request never reaches
the service). Only the role *source* is new — the downstream RBAC/ABAC `authorize` gate is byte-for-
byte unchanged.

Three modes, selected by `SAIR_AUTH` (see [`config.py`](../../src/secure_ai_research/config.py)):

| `SAIR_AUTH` | How the role is established | Dependency |
|-------------|------------------------------|------------|
| `local` (default) | Verifies an HS256 `Authorization: Bearer <jwt>` with a shared secret (`SAIR_AUTH_DEV_SECRET`) — stdlib only, offline, no Keycloak. The role is **authenticated**, not asserted. | `pyjwt` **not** required |
| `oidc` | Verifies an RS256 token against a Keycloak realm's JWKS (`aud`/`iss`/`exp` required). | opt-in `[oidc]` extra (`pyjwt[crypto]`), lazy-imported |
| `insecure` | Restores the old self-asserted `X-Role` header verbatim — **spoofable**, dev only; the factory logs a `WARNING` on selection. | — |

**Fail-closed default.** In `local` mode the shipped placeholder secret (and any secret shorter
than 16 chars) is refused: every request returns **503** unless `SAIR_AUTH_DEV_SECRET` is set to a
strong secret **or** `SAIR_AUTH_ALLOW_DEV_SECRET=1` explicitly opts into the dev secret. So the
default build is never silently forgeable — it either has a real secret or authenticates nothing.

The role claim is read from `SAIR_AUTH_ROLE_CLAIM` (default `role`) and mapped to one of the six
roles above; a non-string/absent claim resolves to an empty role (which `authorize` denies). The
live Keycloak realm wiring and an end-to-end integration test live under the `identity` compose
profile ([`sair-realm.json`](sair-realm.json)).
