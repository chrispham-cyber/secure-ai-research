# Phase 5 Slice 4 — OIDC/Keycloak identity replacing the X-Role dev stub

**Status:** approved-pending (design gate)
**Date:** 2026-11-20
**ROADMAP:** Week 17 — "Keycloak/OIDC identity (replaces the `X-Role` dev stub); RBAC/ABAC enforcement"
**Repo:** `/Users/fox/Chris/CyberBase/secure-ai-research` (local, no remote; **no push without Chris's go**)

---

## 1. Intent & why

Today every research route reads a **self-asserted `X-Role` HTTP header** and passes that string
straight into the authorization gate. `infrastructure/identity/roles.md` names this a "throwaway
stub, not an authentication control — a header is self-asserted and trivially spoofable (threat
T1)." A client picks its own role. The authorization *boundary* is real and well-tested; the
**source of the role is not trustworthy**.

This slice replaces the role source with a **verified, signed token**, leaving the entire
downstream authorization path (`retrieval/authz.py`, `ResearchService`) **byte-for-byte unchanged**
— exactly as roles.md promises: *"the authorization logic downstream of identity does not change —
only the source of the verified role does."*

Per Chris's decisions (2026-11-20), the **default offline posture is itself verified** (not merely
"OIDC available as an option"): the default path checks a real HMAC signature offline, so even
with no Keycloak the role is authenticated, not self-asserted. Keycloak/OIDC is the production
opt-in. The spoofable `X-Role` channel is demoted to an explicit, off-by-default dev flag. And the
default **fails closed on its placeholder secret** so the shipped default is never silently
forgeable (decision A, below).

## 2. Goals / non-goals / anti-goals

**Goals**
- A request's role comes from a **cryptographically verified token**, not a self-asserted header,
  on the default path.
- Three selectable auth modes behind one seam: `local` (default, HS256, offline, stdlib),
  `oidc` (opt-in, RS256/JWKS vs Keycloak), `insecure` (X-Role passthrough, off by default, dev only).
- The OIDC mode is **proven end-to-end against a live Keycloak** (the `identity` compose profile),
  because the image is pullable and "verify live" is a standing lesson.
- Downstream authz/service and the whole hermetic suite's **service-layer** behavior unchanged.
- Default path stays **offline, deterministic, dependency-free** (no new base runtime dependency).

**Non-goals**
- **No interactive login / authorization-code flow / sessions / redirects.** The app is an OIDC
  **resource server**: it *verifies* `Authorization: Bearer <jwt>`; callers obtain tokens out of band.
- **No change to what each role may do.** The six roles and their capabilities (roles.md) are
  unchanged; this slice changes *how the role is established*, not the authz rules. The four
  not-yet-enforced roles gain no new routes.
- **No user/role management UI or API.** Keycloak owns identity; we only consume tokens.
- **No multi-role resolution.** One verified `role` claim (string) in, one role string downstream.
- **No auditing of failed authentications this slice** (decision B): 401 is a boundary rejection
  with zero audit records, like 422. A security-auditor view of failed-auth attempts is a later slice.

**Anti-goals (failure even if it "works")**
- The default path silently accepting an **unsigned / `alg:none` / wrong-algorithm** token (JWT
  alg-confusion). The verifier pins the algorithm.
- A token with **no expiry** being accepted forever — on *either* the local or the OIDC path.
- The hermetic suite importing the OIDC crypto dependency (posture leak) — it must stay out of the
  default path, lazily imported behind an extra (the minio/psycopg pattern).
- An **unhandled 500 with zero audit records**, or a changed audit record, on any path — the
  one-record invariant the project defends everywhere. A provider that raises from its *constructor*
  (missing extra, bad config) must not become an unhandled 500.
- The **shipped default being as forgeable as `X-Role`** — a committed, known secret anyone with
  repo access can mint `senior_analyst` tokens with. Closed by the fail-closed placeholder gate (5.5).
- An **operator misconfiguration or IdP outage surfacing as a client `401`**, indistinguishable from
  a forged token. Infra/identity failures fail closed as **503**, not 401 (5.4).
- A real, usable secret committed to the repo. The HS256 dev secret is a documented placeholder that
  **fails closed**; production uses OIDC.

## 3. Constraints

- Python 3.12; `.venv/bin/python`. TDD; one final opus-xhigh whole-branch review; merge-to-main
  local; **no push**.
- Default path: **stdlib only** (HS256 verification is `hmac` + `hashlib` + base64url + `json` —
  all stdlib). Stdlib has no RSA/EdDSA, which is *why* the default is HS256 (see Approaches).
- OIDC path: `pyjwt[crypto]` behind a new `[oidc]` optional-dependencies extra, **lazy-imported**
  inside the OIDC module only. Importing the default providers must never import `jwt`. The extra is
  **not** added to `requirements-dev.txt` or the SBOM flow (it is opt-in, like `minio`/`psycopg`).
- The `local` default **fails closed on the placeholder secret**: the app refuses to start unless a
  non-placeholder secret is set, or `SAIR_AUTH_ALLOW_DEV_SECRET=1` is explicitly set (5.5).
- PUBLIC/synthetic only. No PII in tokens beyond a role claim and standard JWT claims in tests.
- Keycloak already present: `docker-compose.yml` service `keycloak` (`quay.io/keycloak/keycloak:26.0`,
  profile `identity`, `start-dev`, `127.0.0.1:8080`).

## 4. Approaches

### Posture (decided by Chris): **local verified token by default**
Default offline path verifies a real signature (not self-asserted); OIDC opt-in; X-Role demoted to
an off-by-default insecure dev flag. (Alternative — keep X-Role default, OIDC opt-in only — rejected:
it leaves the spoofable stub as the shipped default.)

### Scope (decided by Chris): **Approach A — full, with live Keycloak proof**
Build the local-HS256 default **and** the real OIDC RS256/JWKS verifier, **and** a live integration
test that provisions a Keycloak realm, mints a real token, and verifies it end-to-end. (Approach B —
ship the OIDC adapter but skip-clean without a hand-configured realm — rejected because Keycloak is
pullable and live verification repeatedly catches real adapter bugs in this project.)

### Default signature algorithm: **HS256 (one sensible way, given dependency-free default)**
To keep the default path dependency-free, verification must be stdlib, and **HS256 is the only JWT
algorithm stdlib can verify**. A "unified asymmetric default" (local RS256 + static JWKS) was
rejected: RS256 verification needs `cryptography`/`pyjwt` **in the base install**, breaking the
dependency-free default every prior slice preserved. So: **default = HS256 (symmetric, stdlib);
OIDC = RS256/JWKS (asymmetric, `[oidc]` extra).**

## 5. The design (decided)

### 5.1 The seam — `identity/` package
```
src/secure_ai_research/identity/
  ports.py       IdentityProvider Protocol + AuthError + IdentityUnavailable
  tokens.py      stdlib HS256 verify (no third-party import)
  providers.py   LocalTokenIdentityProvider, InsecureIdentityProvider (stdlib only)
  oidc.py        OidcIdentityProvider (lazy `import jwt` inside — isolated module)
  factory.py     make_identity_provider(settings)
```

**`ports.py`:**
```python
class IdentityProvider(Protocol):
    def identify(self, *, authorization: str, x_role: str) -> str: ...

class AuthError(Exception):
    """Client credential failed: missing / malformed / bad-signature / expired / wrong-claim
    token. Maps to HTTP 401. Carries an exception-type tag only — never token bytes, signature,
    secret, or key."""

class IdentityUnavailable(Exception):
    """The identity mechanism itself could not run: missing [oidc] extra, JWKS unreachable,
    network/timeout, bad provider config. Maps to HTTP 503 (fail closed), never 401. Type tag only."""
```
`identify` returns the **verified role string** (`""` when the token is valid but carries no/blank
role — downstream authz then denies, deny-by-default). It raises **`AuthError`** for a credential
that is present-but-invalid or required-but-missing (→ **401**), and **`IdentityUnavailable`** for an
infrastructure/config failure (→ **503**). `authorization` is the raw `Authorization` header;
`x_role` is the raw `X-Role` header (used only by the insecure provider).

### 5.2 Three providers
- **`LocalTokenIdentityProvider(secret, *, role_claim, now=time.time)`** — default
  (`SAIR_AUTH=local`). Parses `authorization` as `Bearer <jwt>` (missing/other scheme → `AuthError`),
  verifies via `tokens.verify_hs256(token, secret, now=now)`, then returns the role: a claim that is
  a **non-empty `str`** → `claims[role_claim].strip()`; absent/blank/**non-string** → `""` (never
  `str(None)` → `"None"`). The placeholder-secret gate lives in the factory (5.5), not here.
- **`InsecureIdentityProvider()`** — `SAIR_AUTH=insecure`, dev only. Returns `x_role.strip()`
  (today's behavior); ignores `authorization`; never raises. The **factory logs a `WARNING`** when
  it selects this provider, so "self-announcing" (§6) is implemented, not aspirational.
- **`OidcIdentityProvider(issuer, jwks_url, audience, *, role_claim, timeout)`** — `SAIR_AUTH=oidc`.
  Lives in `oidc.py` with a **lazy `import jwt`**; `ImportError` → **`IdentityUnavailable`**
  (`"oidc extra not installed: pip install '.[oidc]'"`). Built **once** (cached) with a
  `PyJWKClient(jwks_url, timeout=timeout, cache_keys=True)`. Per request:
  `signing_key = client.get_signing_key_from_jwt(token)` then
  `jwt.decode(token, signing_key.key, algorithms=["RS256"], audience=audience, issuer=issuer,
  options={"require": ["exp", "iss", "aud"]})`; return the role from `role_claim` with the same
  non-string→`""` rule as local. **Split the failure modes:** `jwt.ExpiredSignatureError`,
  `InvalidSignatureError`, `InvalidAudienceError`, `InvalidIssuerError`, `DecodeError`,
  `MissingRequiredClaimError` → **`AuthError`** (client's token is bad); JWKS fetch / network /
  timeout / `PyJWKClientError` → **`IdentityUnavailable`** (infra down). Type tag only, no token/key
  in the message.

### 5.3 `tokens.verify_hs256(token, secret, *, now) -> dict` (stdlib, security-critical)
Implemented with `hmac`, `hashlib`, `base64`, `json`. Every rule below is a required unit test.
- **Structure:** exactly three `.`-separated segments; anything else → `AuthError`.
- **base64url:** decode with `base64.urlsafe_b64decode` after re-adding `=` padding; **reject**
  standard-base64 chars (`+`, `/`), internal whitespace, or a decode error → `AuthError`.
- **JSON shape:** header and payload must each decode to a JSON **object** (`dict`); a list, scalar,
  `null`, or non-JSON → `AuthError` (never an `AttributeError`/`TypeError` 500).
- **Algorithm pin:** `header["alg"] == "HS256"` exactly; reject `none`, `RS256`, missing, any other;
  reject a `crit` header (unsupported critical extension) → `AuthError`.
- **Signature:** recompute `HMAC-SHA256(secret.encode("utf-8"), f"{h_b64}.{p_b64}".encode())`;
  compare with `hmac.compare_digest` on **bytes** (constant time); mismatch → `AuthError`.
- **Expiry:** `exp` is **required**; must be a real number (`int`/`float`, **not** `bool`, string,
  `NaN`, or `inf`); reject when `exp <= now()`. `nbf`/`iat` when present must be numeric and consistent
  (`nbf <= now`, `iat` not in the future); **leeway = 0** (deterministic).
- Return the claims dict. Never logs or includes the secret/signature/token in an error.

Signing is **not** production code. A **test-only** helper (`tests/_authtokens.py` →
`mint_hs256(role, *, secret, exp=...)`, plus knobs to forge: wrong alg, no exp, bad sig) feeds the
real verify path.

### 5.4 Wiring — `api/deps.py` + routes
- `@lru_cache def get_identity_provider() -> IdentityProvider: return make_identity_provider(get_settings())`.
  A construction failure (e.g. placeholder-secret gate, 5.5) surfaces at app start / first request as
  a startup error, **not** a silent 500 — and because `lru_cache` does not cache exceptions, the
  factory is written to raise only on genuinely fatal config so it does not thrash per-request.
- New FastAPI dependency `get_role`:
  ```python
  def get_role(authorization: str = Header(default=""), x_role: str = Header(default=""),
               identity: IdentityProvider = Depends(get_identity_provider)) -> str:
      try:
          return identity.identify(authorization=authorization, x_role=x_role)
      except AuthError:
          raise HTTPException(status_code=401, detail="authentication required",
                              headers={"WWW-Authenticate": "Bearer"})
      except IdentityUnavailable:
          raise HTTPException(status_code=503, detail="identity provider unavailable")
  ```
- Each of the **4 routes** (`research_cve`, `research_attack`, `search`, `ask`) swaps
  `x_role: str = Header(default="")` → `role: str = Depends(get_role)` and passes `role=role`. All
  other handler logic unchanged. `/health` and `/version` stay **unauthenticated** (liveness/readiness
  must work without a token; they expose no corpus data).

**401 response contract:** status 401, header `WWW-Authenticate: Bearer`, body the **constant**
`{"detail":"authentication required"}` — **byte-identical** across missing / malformed / bad-sig /
expired, so no auth-failure-reason oracle (mirrors the project's byte-identical-404 discipline).

**Audit-boundary model** (states today's rule explicitly and extends it): a request **rejected at the
HTTP boundary before the service** — 422 (validation), **401** (auth), **503 identity-unavailable** —
emits **zero** audit records; a request that **reaches the service** emits **exactly one**. Decision B
accepts that an anonymous call, audited as DENIED today, is no longer audited (it now 401s before the
service); failed-auth auditing is deferred (§7).

| Condition | Result | Audit |
|---|---|---|
| Missing/invalid/expired/forged token (secure modes) | **401** (in `get_role`) | 0 |
| Identity infra down / missing `[oidc]` extra / JWKS unreachable | **503** (in `get_role`) | 0 |
| Valid token, role not authorized / empty role | existing **403 / 404** | 1 |
| Valid token, authorized | existing **200** | 1 |
| Malformed path/body (with a valid token) | existing **422** | 0 |

**Ordering note:** FastAPI raises dependency `HTTPException`s before path/body validation, so a
malformed request with **no** token returns 401, not 422. That is intended (authenticate first); the
existing 422/no-audit tests therefore must send a valid token to still exercise the 422 path (5.8).

### 5.5 Config (`config.py`) + the fail-closed placeholder gate
```python
auth: Literal["local", "oidc", "insecure"] = "local"
auth_dev_secret: str = "dev-insecure-change-me-not-for-production"   # HS256 dev key (placeholder)
auth_allow_dev_secret: bool = False                                  # explicit opt-in to run on it
auth_role_claim: str = "role"
oidc_issuer: str = "http://localhost:8080/realms/sair"
oidc_jwks_url: str = "http://localhost:8080/realms/sair/protocol/openid-connect/certs"
oidc_audience: str = "sair-api"
oidc_timeout: float = 5.0
```
All `SAIR_`-prefixed. **`make_identity_provider` fail-closes (decision A):** in `local` mode, if
`auth_dev_secret` equals the placeholder **or** is shorter than a floor (e.g. < 16 chars / empty),
it raises `IdentityUnavailable` **unless** `auth_allow_dev_secret` is `True`. So a real deployment
must set a strong `SAIR_AUTH_DEV_SECRET` (or explicitly opt into the dev secret); the shipped default
is not silently forgeable. Tests and local dev set `SAIR_AUTH_ALLOW_DEV_SECRET=1` with a pinned test
secret. Defaults otherwise keep the app offline (local mode, no network).

### 5.6 `[oidc]` extra (`pyproject.toml`)
```toml
oidc = ["pyjwt[crypto]>=2.9,<3.0"]
```
Lazy-imported in `oidc.py` only; the hermetic suite never imports `jwt`. Not in dev requirements/SBOM.

### 5.7 Keycloak realm-import + live integration test
**One concrete wiring (resolves the earlier role-vs-hardcoded ambiguity): a realm role mapped to a
single `role` claim, so a second user with a *different* role yields a *different* claim** (a
hardcoded client mapper would emit the same value for everyone and make the per-user test vacuous).
- `infrastructure/identity/sair-realm.json`: realm `sair`; client `sair-api` with
  `publicClient: true`, `directAccessGrantsEnabled: true` (password grant, no browser); realm roles
  `senior_analyst` and `research_analyst`; **two** users — `senior-test` (role `senior_analyst`) and
  `analyst-test` (role `research_analyst`) — each fully set up (no required actions, password set); a
  **protocol mapper** emitting the user's realm role as a **single String `role` claim** with
  `access.token.claim=true`; and an **audience mapper** adding `sair-api` to `aud` (Keycloak 26
  tokens otherwise carry `aud: account`, which would fail `require: aud`). If a user-attribute
  approach is used instead, the realm must set `unmanagedAttributePolicy` / declare the attribute
  (KC ≥ 24 disables unmanaged attributes by default).
- `docker-compose.yml`: keycloak `command: ["start-dev", "--import-realm"]` + mount
  `./infrastructure/identity:/opt/keycloak/data/import:ro`; realm must import cleanly on restart.
  `oidc_issuer`/`jwks_url` default to `localhost:8080` to match the token `iss` seen over the
  published port.
- `tests/test_integration_keycloak.py` (`-m integration`; **skips clean** when Keycloak is unreachable
  **or** the `[oidc]` extra is absent — a real reachability probe with a timeout, never an
  unconditional skip): via the password grant, mint a token for `senior-test`, run it through
  `OidcIdentityProvider.identify` **and** end-to-end through a `TestClient` route in `oidc` mode →
  role `senior_analyst`, retrieval succeeds; mint for `analyst-test` → role `research_analyst`
  (proves the mapper is per-user, not hardcoded); a **tampered** token → 401; Keycloak-down (bad
  jwks_url) → 503.

### 5.8 Tests migrate to minted tokens; X-Role demoted
- **Every existing `X-Role` call site migrates** — ~31 across `tests/test_api.py`,
  `tests/test_api_generator_wiring.py`, and the integration tests — not only the obvious ones. Three
  classes:
  1. **Header present (`X-Role: <role>`):** → `Authorization: Bearer <mint_hs256(role, secret=TEST_SECRET)>`.
  2. **No header, asserts 403 (anonymous):** these become the new **401, zero-audit** behavior. Keep a
     *separate* test that a **valid token with a blank/unauthorized role** still yields the existing
     **403/404 + one audit** (preserving that path's coverage).
  3. **422/validation + existence-oracle tests:** now send a valid token (else the 401 dependency
     fires first, per 5.4) so they still exercise 422/404/byte-identical bodies.
- **Service-layer tests are untouched** (they call `service.*(role=...)` directly; the seam is above
  them).
- Route tests pin identity via **`app.dependency_overrides[get_identity_provider]`** = a
  `LocalTokenIdentityProvider` with `TEST_SECRET` (avoids `.env` bleed and `lru_cache` leakage);
  tests that drive the factory by env also call **`get_identity_provider.cache_clear()`** alongside
  the existing `get_settings`/`get_service` clears.
- New `tests/test_auth_routes.py`: token→role 200; no token → 401 (+ `WWW-Authenticate: Bearer`, +
  zero audit); bad-signature/expired/`alg:none`/`alg:RS256` → 401 (byte-identical body); valid
  unauthorized role → 403/404; **insecure mode** honors `X-Role` **and** `local` mode *ignores*
  `X-Role` (a request with only `X-Role`, no token → 401); identity-unavailable → 503.
- `tests/test_identity_local.py` (verify_hs256 units — all 5.3 rules); `tests/test_identity_factory.py`
  (mode→provider; **placeholder-secret fail-closed** raises, opt-in allows; oidc branch patched, no
  live connect); `tests/test_identity_oidc_hermetic.py` (importing `providers`/`factory` default path
  does **not** import `jwt` — the minio/psycopg `sys.modules`-pop pattern; missing extra, forced via
  `sys.modules["jwt"]=None`, → `IdentityUnavailable` naming the extra).

### 5.9 Docs
- `infrastructure/identity/roles.md`: rewrite the "Phase-1 development auth (throwaway stub)" section —
  the stub is now off-by-default (`SAIR_AUTH=insecure`, self-announcing), the default is verified
  local tokens (fail-closed on the placeholder secret), OIDC is the production mode; scope the "do not
  expose on a real network" caveat to insecure mode.
- The 4 route docstrings: update the `X-Role` SECURITY note to the verified-token default + the
  401/503 model.
- ROADMAP Week 17 ticked.

## 6. Threat model note
Closes **T1 (self-asserted role)** on the default path: a client can no longer choose its role; it
must present a token signed with a key it does not hold. The committed dev secret does **not** reopen
T1, because `local` mode **fails closed** on it (5.5) — a real deployment sets its own secret or runs
OIDC. Residual: the HS256 dev secret is symmetric, so anyone holding the *configured* secret can mint
tokens — `local` mode is for single-operator/offline use; multi-party production uses `oidc`
(asymmetric, Keycloak holds the private key). The `insecure` mode reopens T1 by design and is
off-by-default, dev-only, and self-announcing (a startup `WARNING`).

## 7. What's left to the builder
- Exact `sair-realm.json` bytes: any realm meeting 5.7's contract (two users, per-user `role` claim,
  `aud: sair-api`, direct-access grant, clean re-import) is fine; the builder tunes mapper type to
  what Keycloak 26 imports cleanly.
- The exact short-secret floor length and whether `iat`-in-future is rejected (5.3 recommends yes).
- Test helper location/signature (`tests/_authtokens.py`), provided it signs HS256 with the test key
  and can forge the negative cases.
- **Deferred (noted, not this slice):** auditing *failed* authentications — **confirmed deferred
  (decision B)**; a security-auditor view of failed-auth/401 attempts is a later slice. Also deferred:
  multi-role (`realm_access.roles`) resolution; token refresh/revocation; rate-limiting auth attempts.

## 8. Definition of done
- 4 routes authorize from a verified token; downstream authz/service byte-unchanged.
- Default `local` mode: offline, stdlib, deterministic; **fails closed on the placeholder secret**;
  hermetic suite never imports `jwt`; full suite green (service-layer counts unchanged, route tests
  migrated to minted tokens, all ~31 `X-Role` sites covered).
- `oidc` mode proven **live against Keycloak** (`-m integration`, per-user claim + 401 + 503 cases);
  skips clean otherwise.
- `insecure` mode off by default, self-announcing, honors X-Role only when set; a default-mode request
  with only `X-Role` → 401.
- 401 (byte-identical body, `WWW-Authenticate`) and 503 (infra) models hold with **zero audit
  records**; no unhandled 500s; one-record-on-service-reach invariant intact.
- roles.md + route docstrings + ROADMAP updated. ruff/black/mypy clean.
- One opus-xhigh whole-branch review → merge-to-main local. **No push.**
