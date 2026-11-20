# Phase 5 Slice 4 — OIDC/Keycloak Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the self-asserted `X-Role` header with verified signed-token identity — an `IdentityProvider` seam whose default is an offline stdlib-HS256 verifier, with an opt-in OIDC/RS256 Keycloak adapter and an off-by-default `insecure` X-Role fallback — leaving the downstream authorization path byte-identical.

**Architecture:** A new `identity/` package mirrors the `storage/`/`retrieval/` seam pattern (ports Protocol + stdlib default + lazy opt-in adapter + factory). A `get_role` FastAPI dependency verifies `Authorization: Bearer <jwt>` and feeds the existing role string into unchanged routes/service/authz. Client-credential failures → 401; identity infra/config failures → 503 (fail-closed); both are boundary rejections with zero audit records. The `local` default fails closed on its placeholder secret.

**Tech Stack:** Python 3.12, FastAPI, stdlib `hmac`/`hashlib`/`base64`/`json` (default verifier), `pyjwt[crypto]` behind an opt-in `[oidc]` extra (lazy-imported), Keycloak 26 (`identity` compose profile) for the live integration test.

**Spec:** `docs/superpowers/specs/2026-11-20-phase5-slice4-oidc-design.md`

## Global Constraints

- Python 3.12; `.venv/bin/python`. Hermetic test cmd: `./.venv/bin/pytest -q -m "not integration"`; integration: `./.venv/bin/pytest -q -m integration`.
- **Default path stdlib-only**; no new base runtime dependency. `pyjwt[crypto]` goes in the `[oidc]` optional-dependencies extra only, **lazy-imported inside `identity/oidc.py`** — importing the default providers/factory must never import `jwt`. The extra is **not** added to `requirements-dev.txt` or the SBOM flow.
- **Downstream authz/service byte-unchanged:** do not edit `retrieval/authz.py` or `research_service.py`. Service-layer tests stay as-is.
- **`local` default fails closed on the placeholder secret** (`"dev-insecure-change-me-not-for-production"`) or a secret shorter than 16 chars, **unless** `SAIR_AUTH_ALLOW_DEV_SECRET=1`.
- **One audit record iff the request reaches the service.** Boundary rejections (422, 401, 503-identity) write **zero** audit records and never an unhandled 500.
- 401 body is the constant `{"detail": "authentication required"}` + header `WWW-Authenticate: Bearer`, **byte-identical** across missing/malformed/bad-sig/expired. 503-identity body: `{"detail": "identity provider unavailable"}`.
- ruff/black line-length 100 (`select = E,F,I,UP,B`); mypy `files=["src"]`, `ignore_missing_imports=true`. Keep all four green.
- Commits end with the attribution footer:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01P3qwAqqTLRSC3U34YkGnFU
  ```
- Local git, no remote. **No push.**

## Review Focus

1. **Alg-confusion** — a token with `alg: none` or `alg: RS256` (no HMAC key held) must be rejected, not accepted. Covered: Task 1 `test_rejects_alg_none`, `test_rejects_alg_rs256`.
2. **Non-object JWT header/payload** (`[]`, `null`, a scalar, non-JSON) must raise `AuthError`, never an `AttributeError`/`TypeError` 500. Covered: Task 1 `test_rejects_non_object_payload`, `test_rejects_non_json_segment`.
3. **A malformed request with no token → 401, not 422** (the dependency fires before body/path validation), and **zero audit records**. Covered: Task 6 `test_cve_no_token_is_401`, Task 5 `test_malformed_body_without_token_is_401`.
4. **IdP outage / missing `[oidc]` extra → 503** (fail-closed), never 401 and never an unhandled 500, with zero audit records. Covered: Task 3 `test_missing_extra_raises_identity_unavailable`, Task 5 `test_identity_unavailable_is_503`.
5. **The placeholder-secret default fails closed** (every request → 503) and the explicit opt-in re-enables it. Covered: Task 4 `test_placeholder_secret_fails_closed`, `test_opt_in_allows_dev_secret`; Task 5 `test_fail_closed_default_is_503`.

---

### Task 1: Identity seam + stdlib HS256 verifier

**Files:**
- Create: `src/secure_ai_research/identity/__init__.py` (empty — symbols imported from submodules, mirrors `storage/__init__.py`)
- Create: `src/secure_ai_research/identity/ports.py`
- Create: `src/secure_ai_research/identity/tokens.py`
- Create: `tests/_authtokens.py` (test-only token minting helper)
- Test: `tests/test_identity_tokens.py`

**Interfaces:**
- Produces:
  - `IdentityProvider(Protocol)` with `identify(self, *, authorization: str, x_role: str) -> str`
  - `AuthError(Exception)` — client credential failure → 401
  - `IdentityUnavailable(Exception)` — infra/config failure → 503
  - `verify_hs256(token: str, secret: str, *, now: float) -> dict` — raises `AuthError` on any invalid token; returns the claims dict
  - `tests/_authtokens.py`: `TEST_SECRET = "test-secret-0123456789abcdef"` (28 chars); `mint_hs256(role="research_analyst", *, secret=TEST_SECRET, exp_delta=3600.0, now=None, role_claim="role", alg="HS256", include_exp=True, sign_with=None, extra=None) -> str` where **`now=None` means real `time.time()`** (so route tokens are valid against the runtime provider's `time.time()`; the verify unit tests pass an explicit `now=NOW`). Forge knobs: `alg` sets the header alg incl. `"none"`; `include_exp=False` omits exp; `sign_with` signs with a different secret; `extra` merges extra claims last (so `extra={"exp": ...}`/`{"role": ...}` overrides).

- [ ] **Step 1: Write the failing tests** in `tests/test_identity_tokens.py` — one per 5.3 rule, using `_authtokens.mint_hs256` and raw-built tokens. `NOW = 1_000_000.0`.

```python
def test_valid_token_returns_claims():
    tok = mint_hs256("senior_analyst", now=NOW)
    claims = verify_hs256(tok, TEST_SECRET, now=NOW)
    assert claims["role"] == "senior_analyst"

def test_rejects_bad_signature():
    tok = mint_hs256(sign_with="wrong-secret-0123456789", now=NOW)
    with pytest.raises(AuthError): verify_hs256(tok, TEST_SECRET, now=NOW)

def test_rejects_alg_none():
    tok = mint_hs256(alg="none", now=NOW)
    with pytest.raises(AuthError): verify_hs256(tok, TEST_SECRET, now=NOW)

def test_rejects_alg_rs256():          # alg-confusion: HS verifier must not accept an RS header
    tok = mint_hs256(alg="RS256", now=NOW)
    with pytest.raises(AuthError): verify_hs256(tok, TEST_SECRET, now=NOW)

def test_requires_exp():
    tok = mint_hs256(include_exp=False, now=NOW)
    with pytest.raises(AuthError): verify_hs256(tok, TEST_SECRET, now=NOW)

def test_rejects_expired():
    tok = mint_hs256(exp_delta=-1.0, now=NOW)
    with pytest.raises(AuthError): verify_hs256(tok, TEST_SECRET, now=NOW)

def test_rejects_non_numeric_exp():    # exp as bool/str/NaN/inf
    for bad in (True, "soon", float("nan"), float("inf")):
        tok = mint_hs256(extra={"exp": bad}, include_exp=False, now=NOW)
        with pytest.raises(AuthError): verify_hs256(tok, TEST_SECRET, now=NOW)

def test_rejects_non_object_payload():    # payload is a JSON list / scalar / null, not an object
    # build raw token: urlsafe_b64(header{"alg":"HS256"}) . urlsafe_b64("[]") . <hmac sig>
    with pytest.raises(AuthError): verify_hs256(raw_token_with_payload(b"[]"), TEST_SECRET, now=NOW)

def test_rejects_non_json_segment():      # payload not valid JSON at all
    with pytest.raises(AuthError): verify_hs256(raw_token_with_payload(b"\xff\xff"), TEST_SECRET, now=NOW)

def test_rejects_standard_base64_chars():  # '+'/'/' are not base64url
    with pytest.raises(AuthError): verify_hs256("ab+/.ab+/.sig", TEST_SECRET, now=NOW)

def test_rejects_wrong_segment_count():
    with pytest.raises(AuthError): verify_hs256("only.two", TEST_SECRET, now=NOW)

def test_rejects_crit_header():
    tok = raw_token_with_header({"alg": "HS256", "crit": ["x"]})
    with pytest.raises(AuthError): verify_hs256(tok, TEST_SECRET, now=NOW)
```

- [ ] **Step 2: Run the tests, verify they fail** — `./.venv/bin/pytest tests/test_identity_tokens.py -q`. Expected: FAIL (`ModuleNotFoundError: secure_ai_research.identity`).

- [ ] **Step 3: Implement** `ports.py` (the Protocol + two Exception subclasses, docstrings per spec 5.1) and `verify_hs256` in `tokens.py` per spec §5.3: 3-segment split; `base64.urlsafe_b64decode` with re-added `=` padding, rejecting `+`/`/`/whitespace/decode-error; header & payload must each `json.loads` to a `dict`; pin `header["alg"] == "HS256"` and reject a `crit` header; recompute `hmac.new(secret.encode("utf-8"), f"{h}.{p}".encode(), hashlib.sha256)` and `hmac.compare_digest` the raw signature bytes; require numeric non-bool finite `exp` and reject `exp <= now`; validate `nbf`/`iat` when present (leeway 0, `iat` not in the future). Also write `tests/_authtokens.py` with `mint_hs256` + the `raw_token_with_*` helpers the tests use.

- [ ] **Step 4: Run the tests, verify they pass** — `./.venv/bin/pytest tests/test_identity_tokens.py -q`. Expected: PASS.

- [ ] **Step 5: Lint + commit** — `./.venv/bin/ruff check src/secure_ai_research/identity tests/test_identity_tokens.py tests/_authtokens.py && ./.venv/bin/black --check src/secure_ai_research/identity tests/_authtokens.py tests/test_identity_tokens.py && ./.venv/bin/mypy src`.
```bash
git add src/secure_ai_research/identity/__init__.py src/secure_ai_research/identity/ports.py src/secure_ai_research/identity/tokens.py tests/_authtokens.py tests/test_identity_tokens.py
git commit -m "feat(identity): stdlib HS256 verifier + IdentityProvider seam (Slice 4 Task 1)"
```

---

### Task 2: Local + Insecure providers

**Files:**
- Create: `src/secure_ai_research/identity/providers.py`
- Test: `tests/test_identity_providers.py`

**Interfaces:**
- Consumes: `AuthError` + `verify_hs256` (Task 1), `mint_hs256`/`TEST_SECRET` (Task 1).
- Produces:
  - `LocalTokenIdentityProvider(secret: str, *, role_claim: str = "role", now: Callable[[], float] = time.time)` implementing `identify(*, authorization, x_role) -> str`
  - `InsecureIdentityProvider()` implementing `identify(*, authorization, x_role) -> str`

- [ ] **Step 1: Write the failing tests** in `tests/test_identity_providers.py`:

```python
def test_local_bearer_token_yields_role():
    p = LocalTokenIdentityProvider(TEST_SECRET, now=lambda: NOW)
    assert p.identify(authorization=f"Bearer {mint_hs256('senior_analyst', now=NOW)}", x_role="") == "senior_analyst"

def test_local_missing_authorization_raises():
    p = LocalTokenIdentityProvider(TEST_SECRET, now=lambda: NOW)
    with pytest.raises(AuthError): p.identify(authorization="", x_role="research_analyst")  # X-Role ignored

def test_local_non_bearer_scheme_raises():
    p = LocalTokenIdentityProvider(TEST_SECRET, now=lambda: NOW)
    with pytest.raises(AuthError): p.identify(authorization="Basic abc", x_role="")

def test_local_blank_or_missing_role_claim_is_empty_string():
    p = LocalTokenIdentityProvider(TEST_SECRET, now=lambda: NOW)
    assert p.identify(authorization=f"Bearer {mint_hs256(extra={'role': None}, role='x', now=NOW)}", x_role="") == ""
    # a non-string role claim must become "" (never "None"); absent claim → ""

def test_insecure_returns_x_role():
    assert InsecureIdentityProvider().identify(authorization="", x_role=" senior_analyst ") == "senior_analyst"
```

- [ ] **Step 2: Run, verify fail** — `./.venv/bin/pytest tests/test_identity_providers.py -q`. Expected: FAIL (ImportError).

- [ ] **Step 3: Implement** `providers.py`. `LocalTokenIdentityProvider.identify`: split `authorization` into scheme+token, require `scheme.lower() == "bearer"` and a token (else `AuthError`); `claims = verify_hs256(token, self._secret, now=self._now())`; `r = claims.get(self._role_claim)`; return `r.strip() if isinstance(r, str) else ""`. `InsecureIdentityProvider.identify` returns `x_role.strip()`.

- [ ] **Step 4: Run, verify pass.** Expected: PASS.

- [ ] **Step 5: Lint + commit**
```bash
git add src/secure_ai_research/identity/providers.py tests/test_identity_providers.py
git commit -m "feat(identity): local HS256 + insecure X-Role providers (Slice 4 Task 2)"
```

---

### Task 3: OIDC provider (lazy) + hermetic posture guards

**Files:**
- Create: `src/secure_ai_research/identity/oidc.py`
- Test: `tests/test_identity_oidc_hermetic.py`

**Interfaces:**
- Consumes: `AuthError`, `IdentityUnavailable` (Task 1).
- Produces: `OidcIdentityProvider(issuer: str, jwks_url: str, audience: str, *, role_claim: str = "role", timeout: float = 5.0)` implementing `identify(*, authorization, x_role) -> str`. **`jwt` is imported lazily inside `identify` (memoised), never at module top or in `__init__`.** Missing extra → `IdentityUnavailable` naming the extra. (Real RS256/JWKS decode is proven only in Task 7 integration, like the minio/pgvector adapters — the hermetic venv has no `pyjwt`.)

- [ ] **Step 1: Write the failing tests** (mirror `tests/test_minio_adapter.py`):

```python
def test_importing_oidc_module_does_not_import_jwt():
    if "jwt" in sys.modules: pytest.skip("jwt already loaded by another test")
    sys.modules.pop("secure_ai_research.identity.oidc", None)
    importlib.import_module("secure_ai_research.identity.oidc")
    assert "jwt" not in sys.modules

def test_missing_extra_raises_identity_unavailable(monkeypatch):
    # force ImportError for jwt regardless of whether the extra is installed
    real_import = builtins.__import__
    def fake_import(name, *a, **k):
        if name == "jwt" or name.startswith("jwt."): raise ImportError("No module named 'jwt'")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    p = OidcIdentityProvider("iss", "http://localhost:8080/jwks", "sair-api")
    with pytest.raises(IdentityUnavailable) as exc:
        p.identify(authorization="Bearer x.y.z", x_role="")
    assert "oidc" in str(exc.value).lower()  # names the extra to install
```

- [ ] **Step 2: Run, verify fail.** Expected: FAIL (ImportError on the module).

- [ ] **Step 3: Implement** `oidc.py` per spec §5.2: `__init__` stores config only. `identify`: parse Bearer token (missing/scheme → `AuthError`); lazily `import jwt` (`ImportError` → `IdentityUnavailable("oidc extra not installed: pip install '.[oidc]'")`); build+cache `jwt.PyJWKClient(self._jwks_url, timeout=self._timeout, cache_keys=True)` on `self`; `key = client.get_signing_key_from_jwt(token)`; `claims = jwt.decode(token, key.key, algorithms=["RS256"], audience=self._audience, issuer=self._issuer, options={"require": ["exp", "iss", "aud"]})`; return the role (`isinstance(... , str)` else `""`). Map `jwt.InvalidTokenError` subclasses (expired/bad-sig/aud/iss/decode/missing-claim) → `AuthError`; `jwt.PyJWKClientError`/`OSError`/URL/timeout → `IdentityUnavailable`. Message carries the exception type name only — no token/key.

- [ ] **Step 4: Run, verify pass.** Also run the full hermetic suite to prove nothing imports `jwt`: `./.venv/bin/pytest -q -m "not integration"`. Expected: PASS, no import errors.

- [ ] **Step 5: Lint + commit**
```bash
git add src/secure_ai_research/identity/oidc.py tests/test_identity_oidc_hermetic.py
git commit -m "feat(identity): lazy OIDC/RS256 provider + hermetic guards (Slice 4 Task 3)"
```

---

### Task 4: Config + factory (fail-closed placeholder gate)

**Files:**
- Modify: `src/secure_ai_research/config.py` (add auth settings after `data_classification`)
- Create: `src/secure_ai_research/identity/factory.py`
- Test: `tests/test_identity_factory.py`

**Interfaces:**
- Consumes: `LocalTokenIdentityProvider`, `InsecureIdentityProvider` (Task 2); `OidcIdentityProvider` (Task 3); `Settings` (config).
- Produces: `make_identity_provider(settings: Settings) -> IdentityProvider`. **Never raises at construction.** For `local` mode with a placeholder/short secret and no opt-in, it returns a provider whose `identify` always raises `IdentityUnavailable` (`_UnavailableProvider`, defined in `factory.py`) and logs a `WARNING`. For `insecure` mode it logs a `WARNING` (self-announcing, §6). Config fields (spec §5.5):
  `auth: Literal["local","oidc","insecure"] = "local"`; `auth_dev_secret: str = "dev-insecure-change-me-not-for-production"`; `auth_allow_dev_secret: bool = False`; `auth_role_claim: str = "role"`; `oidc_issuer`, `oidc_jwks_url`, `oidc_audience`, `oidc_timeout: float = 5.0` (defaults per spec).

- [ ] **Step 1: Write the failing tests** in `tests/test_identity_factory.py`:

```python
def test_default_is_local_provider():
    s = Settings(auth_allow_dev_secret=True)  # strong enough to not fail-closed
    assert isinstance(make_identity_provider(s), LocalTokenIdentityProvider)

def test_placeholder_secret_fails_closed():
    p = make_identity_provider(Settings())        # placeholder secret, no opt-in
    with pytest.raises(IdentityUnavailable):
        p.identify(authorization="Bearer x", x_role="")

def test_short_secret_fails_closed():
    p = make_identity_provider(Settings(auth_dev_secret="short"))
    with pytest.raises(IdentityUnavailable):
        p.identify(authorization="Bearer x", x_role="")

def test_opt_in_allows_dev_secret():
    s = Settings(auth_allow_dev_secret=True)       # placeholder + explicit opt-in
    assert isinstance(make_identity_provider(s), LocalTokenIdentityProvider)

def test_strong_secret_needs_no_opt_in():
    s = Settings(auth_dev_secret="a-strong-secret-0123456789")
    assert isinstance(make_identity_provider(s), LocalTokenIdentityProvider)

def test_oidc_mode_builds_oidc_provider():
    assert isinstance(make_identity_provider(Settings(auth="oidc")), OidcIdentityProvider)

def test_insecure_mode_warns(caplog):
    with caplog.at_level("WARNING"):
        assert isinstance(make_identity_provider(Settings(auth="insecure")), InsecureIdentityProvider)
    assert any("insecure" in r.message.lower() for r in caplog.records)
```

- [ ] **Step 2: Run, verify fail** — `./.venv/bin/pytest tests/test_identity_factory.py -q`. Expected: FAIL (no `factory` / no config fields).

- [ ] **Step 3: Implement** the config fields (plain pydantic fields, `SAIR_`-prefixed by the existing `env_prefix`) and `make_identity_provider`: branch on `settings.auth`; `insecure` → log WARNING, `InsecureIdentityProvider()`; `oidc` → `OidcIdentityProvider(settings.oidc_issuer, settings.oidc_jwks_url, settings.oidc_audience, role_claim=settings.auth_role_claim, timeout=settings.oidc_timeout)`; `local` → if `(auth_dev_secret == PLACEHOLDER or len(auth_dev_secret) < 16) and not auth_allow_dev_secret`: log WARNING + return `_UnavailableProvider("local auth secret is the insecure placeholder; set SAIR_AUTH_DEV_SECRET or SAIR_AUTH_ALLOW_DEV_SECRET=1")`; else `LocalTokenIdentityProvider(auth_dev_secret, role_claim=auth_role_claim)`. Define `PLACEHOLDER` as a module constant equal to the config default.

- [ ] **Step 4: Run, verify pass.** Expected: PASS.

- [ ] **Step 5: Lint + commit** (`mypy src` included)
```bash
git add src/secure_ai_research/config.py src/secure_ai_research/identity/factory.py tests/test_identity_factory.py
git commit -m "feat(identity): config + fail-closed factory (Slice 4 Task 4)"
```

---

### Task 5: Wire the API — deps, routes, `[oidc]` extra, docs

**Files:**
- Modify: `src/secure_ai_research/api/deps.py` (add `get_identity_provider` + `get_role`)
- Modify: `src/secure_ai_research/api/routers/research.py` (swap `x_role` for `role=Depends(get_role)` on all 4 routes; update the 4 SECURITY docstrings)
- Modify: `pyproject.toml` (add the `[oidc]` extra after `minio`)
- Modify: `infrastructure/identity/roles.md` (rewrite the "Phase-1 development auth (throwaway stub)" section per spec §5.9)
- Modify: `ROADMAP.md` (tick Week 17)
- Append: `tests/_authtokens.py` (add `pinned_local_identity()`)
- Test: `tests/test_auth_routes.py`

**Interfaces:**
- Consumes: `make_identity_provider` (Task 4), `AuthError`/`IdentityUnavailable` (Task 1), existing `get_service`.
- Produces: `@lru_cache get_identity_provider() -> IdentityProvider`; `get_role(authorization=Header(""), x_role=Header(""), identity=Depends(get_identity_provider)) -> str`; `tests/_authtokens.py::pinned_local_identity() -> LocalTokenIdentityProvider` (bound to `TEST_SECRET`).

**Ruling (record in the ledger):** `get_role` injects the provider via `Depends(get_identity_provider)` so tests can override it, and the fail-closed / missing-extra / infra failures raise inside `identify()` (never from `get_identity_provider` construction) so they are caught by `get_role` → 503, never an uncaught 500. This implements the spec's "must not become an unhandled 500" as fail-closed **503-per-request** (equivalent security outcome to refuse-to-boot, without making `import app` fatal under default settings).

- [ ] **Step 1: Write the failing tests** in `tests/test_auth_routes.py`. A `service` fixture overrides `get_service` (building the service on `tmp_path/"audit.jsonl"`, indexing the nvd sample like `test_api.py`) and **yields that audit path**; zero-audit is asserted with `not service.exists()`, one-audit with `len(read_records(service)) == 1`. Auth mode is driven by `monkeypatch.setenv` + `get_settings.cache_clear()` + `get_identity_provider.cache_clear()`; tokens minted with `TEST_SECRET`. Set `SAIR_AUTH_ALLOW_DEV_SECRET=1` + `SAIR_AUTH_DEV_SECRET=TEST_SECRET` for the local happy/401 cases.

```python
def test_token_authorizes(service, local_auth):
    r = client.get("/research/cve/CVE-2099-0001", headers=bearer("research_analyst"))
    assert r.status_code == 200

def test_no_token_is_401(service, local_auth):
    r = client.get("/research/cve/CVE-2099-0001")
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"] == "Bearer"
    assert r.json() == {"detail": "authentication required"}
    assert not service.exists()                           # service fixture yields the audit path → 0 records

def test_bad_signature_and_expired_and_alg_none_are_401_byte_identical(service, local_auth):
    bodies = set()
    for tok in (mint_hs256(sign_with="nope-0123456789abc"), mint_hs256(exp_delta=-1), mint_hs256(alg="none")):
        r = client.get("/research/cve/CVE-2099-0001", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 401
        bodies.add(r.text)
    assert len(bodies) == 1                               # no auth-failure-reason oracle

def test_unauthorized_role_token_is_403(service, local_auth):
    r = client.get("/research/cve/CVE-2099-0001", headers=bearer("security_auditor"))
    assert r.status_code == 403

def test_malformed_body_without_token_is_401(service, local_auth):   # 401 fires before 422
    r = client.post("/research/search", json={"query": "   "})
    assert r.status_code == 401

def test_fail_closed_default_is_503(service, monkeypatch):
    monkeypatch.delenv("SAIR_AUTH_ALLOW_DEV_SECRET", raising=False)
    monkeypatch.setenv("SAIR_AUTH_DEV_SECRET", "dev-insecure-change-me-not-for-production")
    _reload_auth()
    r = client.get("/research/cve/CVE-2099-0001", headers=bearer("research_analyst"))
    assert r.status_code == 503

def test_insecure_mode_honors_x_role_and_local_ignores_it(service, monkeypatch):
    monkeypatch.setenv("SAIR_AUTH", "insecure"); _reload_auth()
    assert client.get("/research/cve/CVE-2099-0001", headers={"X-Role": "research_analyst"}).status_code == 200
    monkeypatch.setenv("SAIR_AUTH", "local"); monkeypatch.setenv("SAIR_AUTH_ALLOW_DEV_SECRET", "1")
    monkeypatch.setenv("SAIR_AUTH_DEV_SECRET", TEST_SECRET); _reload_auth()
    assert client.get("/research/cve/CVE-2099-0001", headers={"X-Role": "research_analyst"}).status_code == 401

def test_identity_unavailable_is_503(service, monkeypatch):
    monkeypatch.setenv("SAIR_AUTH", "oidc"); monkeypatch.setenv("SAIR_OIDC_JWKS_URL", "http://127.0.0.1:1/jwks")
    _reload_auth()
    r = client.get("/research/cve/CVE-2099-0001", headers=bearer("research_analyst"))
    assert r.status_code == 503   # missing extra OR unreachable JWKS — both fail closed
```
(`_reload_auth()` = `get_settings.cache_clear(); get_identity_provider.cache_clear()`; `bearer(role)` = `{"Authorization": f"Bearer {mint_hs256(role)}"}`; `local_auth` fixture sets the two SAIR_AUTH_* env + `_reload_auth` + clears after.)

- [ ] **Step 2: Run, verify fail** — `./.venv/bin/pytest tests/test_auth_routes.py -q`. Expected: FAIL (no `get_role`).

- [ ] **Step 3: Implement.** In `deps.py`: `@lru_cache def get_identity_provider(): return make_identity_provider(get_settings())`; `get_role` per spec §5.4 (try `identity.identify(...)`; `AuthError` → `HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})`; `IdentityUnavailable` → `HTTPException(503, "identity provider unavailable")`). In `research.py`: replace each `x_role: str = Header(default="")` with `role: str = Depends(get_role)`, change `role=x_role` → `role=role`, and rewrite the SECURITY docstring block to describe the verified-token default + the 401/503 model + `insecure` dev flag. Add `pinned_local_identity()` to `_authtokens.py`. Add `oidc = ["pyjwt[crypto]>=2.9,<3.0"]` to `[project.optional-dependencies]`. Rewrite the roles.md stub section and tick ROADMAP Week 17.

- [ ] **Step 4: Run, verify pass** — `./.venv/bin/pytest tests/test_auth_routes.py -q`. Expected: PASS.

- [ ] **Step 5: Lint + commit** (`mypy src`)
```bash
git add src/secure_ai_research/api/deps.py src/secure_ai_research/api/routers/research.py pyproject.toml infrastructure/identity/roles.md ROADMAP.md tests/_authtokens.py tests/test_auth_routes.py
git commit -m "feat(api): verified-token get_role dependency + route swap + [oidc] extra (Slice 4 Task 5)"
```

---

### Task 6: Migrate existing route tests off X-Role

**Files:**
- Modify: `tests/test_api.py` (28 X-Role sites; add `_pin_identity` autouse fixture; split the 4 no-token-403 tests)
- Modify: `tests/test_api_generator_wiring.py` (2 sites + `_pin_identity`)
- Modify: `tests/test_nvd_fetch_integration.py` (1 site + `_pin_identity`, integration)

**Interfaces:**
- Consumes: `get_identity_provider` (Task 5), `pinned_local_identity`/`mint_hs256` (Task 5/1).

- [ ] **Step 1: Add the pin fixture + token helper** to each file:
```python
from secure_ai_research.api.deps import get_identity_provider
from tests._authtokens import mint_hs256, pinned_local_identity

@pytest.fixture(autouse=True)
def _pin_identity():
    app.dependency_overrides[get_identity_provider] = pinned_local_identity
    yield
    app.dependency_overrides.pop(get_identity_provider, None)

def _bearer(role): return {"Authorization": f"Bearer {mint_hs256(role)}"}
```

- [ ] **Step 2: Replace every `headers={"X-Role": "<role>"}` with `headers=_bearer("<role>")`** across the three files (28 + 2 + 1). Mechanical; `mint_hs256` default `now`/`exp` keep tokens valid.

- [ ] **Step 3: Split the 4 no-token tests** in `test_api.py` — `test_cve_missing_role_denied` (l.65), `test_attack_missing_role_denied` (l.270), `test_search_missing_role_denied` (l.411), `test_ask_missing_role_is_403` (l.473). Each becomes two: `test_<route>_no_token_is_401` (no `Authorization` header → **401**; take `tmp_path` alongside the fixture and assert `not (tmp_path / "audit.jsonl").exists()` — the `service`/`_override_*` fixtures build audit there, and 401 never reaches the service) and `test_<route>_unauthorized_role_is_403` (`_bearer("security_auditor")` → **403**). `test_cve_unknown_role_denied` (l.70) already covers cve's 403 via a token now — keep it.

- [ ] **Step 4: Run the full hermetic suite** — `./.venv/bin/pytest -q -m "not integration"`. Expected: PASS (service-layer counts unchanged; all route tests now token-authenticated). Fix any site missed by the mechanical pass.

- [ ] **Step 5: Lint + commit**
```bash
git add tests/test_api.py tests/test_api_generator_wiring.py tests/test_nvd_fetch_integration.py
git commit -m "test: migrate route tests from X-Role to verified Bearer tokens (Slice 4 Task 6)"
```

---

### Task 7: Keycloak realm-import + live integration proof

**Files:**
- Create: `infrastructure/identity/sair-realm.json`
- Modify: `docker-compose.yml` (keycloak `--import-realm` + mount `./infrastructure/identity:/opt/keycloak/data/import:ro`)
- Create: `tests/test_integration_keycloak.py` (`pytestmark = pytest.mark.integration`)

**Interfaces:**
- Consumes: `OidcIdentityProvider` (Task 3), `make_identity_provider`/Settings (Task 4), `get_identity_provider`/`get_service` overrides (Task 5).
- Realm contract (spec §5.7): realm `sair`; client `sair-api` (`publicClient: true`, `directAccessGrantsEnabled: true`); realm roles `senior_analyst` + `research_analyst`; users `senior-test`/`analyst-test` (fully set up, password set, respective role); a **per-user realm-role → single String `role` claim** mapper (`access.token.claim=true`); an **audience mapper** adding `sair-api` to `aud`. Realm must re-import cleanly on restart.

- [ ] **Step 1: Write the integration tests** (`-m integration`; `jwt` imported only inside functions; skip-clean via a real reachability probe). `_require_keycloak()` = `pytest.importorskip("jwt")` + a `GET` on the realm's OIDC config with a timeout → `pytest.skip` on any failure.
```python
def _token(user, pw="pw"):   # password grant against the live Keycloak
    import urllib.request, urllib.parse, json
    ...  # POST /realms/sair/protocol/openid-connect/token, return access_token

def test_senior_token_resolves_senior_role():
    _require_keycloak()
    p = OidcIdentityProvider(ISSUER, JWKS_URL, "sair-api")
    assert p.identify(authorization=f"Bearer {_token('senior-test')}", x_role="") == "senior_analyst"

def test_per_user_claim_is_not_hardcoded():
    _require_keycloak()
    p = OidcIdentityProvider(ISSUER, JWKS_URL, "sair-api")
    assert p.identify(authorization=f"Bearer {_token('analyst-test')}", x_role="") == "research_analyst"

def test_end_to_end_route_in_oidc_mode_authorizes():
    _require_keycloak()
    # SAIR_AUTH=oidc via Settings override on get_identity_provider + get_service override;
    # real Keycloak token → GET /research/cve → 200
    ...

def test_tampered_token_is_401():
    _require_keycloak()
    p = OidcIdentityProvider(ISSUER, JWKS_URL, "sair-api")
    tok = _token("senior-test")[:-3] + "zzz"
    with pytest.raises(AuthError): p.identify(authorization=f"Bearer {tok}", x_role="")

def test_unreachable_jwks_is_identity_unavailable():
    _require_keycloak()
    p = OidcIdentityProvider(ISSUER, "http://127.0.0.1:1/jwks", "sair-api")
    with pytest.raises(IdentityUnavailable): p.identify(authorization=f"Bearer {_token('senior-test')}", x_role="")
```

- [ ] **Step 2: Verify hermetic collection stays clean** — `./.venv/bin/pytest -q -m "not integration"`. Expected: PASS, and the new file is collected but **deselected** (no `jwt` import at module top).

- [ ] **Step 3: Author `sair-realm.json` + compose wiring** per the realm contract. Then bring up Keycloak and install the extra:
```bash
docker compose --profile identity up -d keycloak
./.venv/bin/pip install -e '.[oidc]'
```

- [ ] **Step 4: Run the live integration tests** — `./.venv/bin/pytest tests/test_integration_keycloak.py -q -m integration`. Expected: PASS against live Keycloak. **If Keycloak/the image is unavailable in this environment**, record the blocker honestly in the ledger (hermetic guards + skip-clean stand; live proof deferred), per the Slice-3 MinIO precedent — do not claim a live pass that did not happen.

- [ ] **Step 5: Commit**
```bash
git add infrastructure/identity/sair-realm.json docker-compose.yml tests/test_integration_keycloak.py
git commit -m "feat(identity): Keycloak realm-import + live OIDC integration test (Slice 4 Task 7)"
```

---

## Notes for the executor
- After Task 7: full hermetic suite green, then the **one opus-xhigh whole-branch review** (fresh reviewer), re-grade findings by effect, Critical/Important → one TDD fix pass, Minor → ledger. Then superpowers:finishing-a-development-branch → **Option 1 merge-to-main local** (pre-authorized), **no push**.
- The design doc + this plan are committed together at branch start (see handoff).
- Do **not** touch `retrieval/authz.py` or `research_service.py` — the downstream-unchanged invariant is a review gate.
