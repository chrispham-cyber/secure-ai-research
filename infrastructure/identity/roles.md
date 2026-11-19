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

## Phase-1 development auth (throwaway stub)

Phase 1 does **not** stand up an identity provider. For local development only, a role is
asserted with a request header:

```
X-Role: research_analyst
```

This maps the header value to one of the six roles above. **It is a throwaway stub and not
an authentication control** — a header is self-asserted and trivially spoofable (threat
T1). It exists so the authorization *boundary* can be built and tested in Phase 1.

**Phase 5 replaces it** with Keycloak/OIDC (optional `identity` compose profile today):
roles come from signed tokens, and the `X-Role` shortcut is removed. The authorization
logic downstream of identity does not change — only the source of the verified role does.
