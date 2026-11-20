# Phase 5 Slice 5 — Encryption, Secret Management & Tamper-Evident Audit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the audit trail tamper-evident (hash-chain + HMAC, default-on), add a fail-closed-in-prod secret-management seam, an opt-in at-rest cipher seam, and an in-transit posture check — without changing the deterministic pipeline output.

**Architecture:** Four seams, each opt-in behind the default stdlib/offline path. A `secret/` package centralizes secret sourcing + a prod-only fail-closed gate; a `crypto/` package is a `Cipher` seam (NullCipher default, opt-in FernetCipher); `audit/signing.py` wraps each record in a signed envelope (keyless SHA-256 chain + keyed HMAC-SHA256) that `audit/record.py` writes through `emit`/reads through `read_records` (which still returns `ResearchRecord`); a startup lifespan wires verification and fails closed in prod.

**Tech Stack:** Python 3.12, stdlib `hmac`/`hashlib`/`fcntl`/`json`, pydantic v2, FastAPI lifespan; `cryptography` (Fernet) opt-in behind a new `[crypto]` extra.

**Spec:** `docs/superpowers/specs/2026-11-20-phase5-slice5-crypto-audit-design.md`

## Global Constraints

- Python `>=3.12`; stdlib-only on the default path. `cryptography>=43,<47` lives ONLY in a new `[crypto]` extra; the hermetic suite (`-m "not integration"`) never imports it.
- **Pipeline output stays byte-identical** (answers, citations, the Phase-4 `grounding 1.0 / citation 0.7742` gate). The audit **file format** changes to a signed envelope by design (signing is default-on, Chris's decision); `read_records()` still returns `ResearchRecord`, so in-memory consumers are unaffected.
- **Audit signing is DEFAULT-ON**: keyless SHA-256 hash-chain always + keyed HMAC-SHA256 with a **dev-default key** (`DEV_AUDIT_KEY`), so dev runs unchanged. Fail-closed refusal bites **only** in prod mode (`require_strong_secrets=True`).
- **One audit record per request; no untrusted *request input* causes an unhandled 500 or a missing record.** (A local disk/log operational fault is outside this invariant.)
- Do **not** change `retrieval/authz.py` or `research_service.py` *pipeline logic*. The only service edits allowed: ctor gains `audit_key`/`audit_cipher` (defaults keep every existing construction working), the 5 `emit(...)` call sites gain `key=`/`cipher=`, and `_emit_terminal` guards its own `emit`.
- Concurrency: `fcntl.flock(LOCK_EX)` + a module `threading.Lock` around read-head→append. POSIX single-process is the supported/tested config.
- **Honest scope (do not over-claim in code, comments, or docs):** tamper-**evidence**, not WORM; tail-truncation is undetected without an external anchor; HMAC is symmetric (the key-holder can rewrite history).
- Test command: `./.venv/bin/pytest -q -m "not integration"`; integration: `./.venv/bin/pytest -q -m integration`.
- **Scope trim from the approved design (builder call, YAGNI):** the optional `audit_key`/`audit_cipher` params on `research_from_source` are **not** added this slice — no prod-CLI use case exists, and CLI/demo/benchmark tools keep working with their own dev-key logs. The one-key-per-log rule is documented in `docs/phase5-encryption-transit.md` instead.

## Review Focus

1. **Tail truncation is honestly undetected** — dropping the last K lines leaves a shorter but valid chain; `verify_chain` returns `ok=True`. Pinned by a test so no future reader mistakes this for WORM. (Task 3)
2. **Mid-stream tamper is caught at the right seq** — editing record N, reordering two records, or flipping one HMAC byte each make `verify_chain` return `ok=False` with `first_bad_seq` set. (Task 3)
3. **Fail-closed bites only in prod** — `verify_secrets` is a no-op on default dev placeholders and raises `SecretError` (naming the setting, never the value) when `require_strong_secrets=True`; backend secrets checked only when that backend is active; prod overrides `auth_allow_dev_secret`. (Task 1)
4. **`read_records` unchanged + eval gate green** — existing audit-reading consumers still get `ResearchRecord`; the Phase-4 regression gate stays green and never reads audit *bytes*. (Tasks 3, 5)
5. **Opt-in cipher round-trips and never imports `cryptography` by default** — `NullCipher` identity; missing `[crypto]` extra or a bad key → `CipherError`; `"cryptography" not in sys.modules` after the hermetic suite; Fernet round-trip under `-m integration`. (Task 2)
6. **Secrets never leak** — a provoked `SecretError`/`CipherError` message contains no secret substring; `redact` replaces known secrets. (Tasks 1, 2)
7. **Canonicalization round-trips (no false tamper)** — a record with a tz-aware microsecond `timestamp`, a unicode `objective`, and a float inside `tool_invocations` passes `verify_chain` after a real write→read (the dump→parse→dump must be byte-idempotent). (Task 3)

---

### Task 1: Config additions + secret-management seam (`secret/`)

**Files:**
- Modify: `src/secure_ai_research/config.py` (add Slice-5 fields after line 84)
- Create: `src/secure_ai_research/secret/__init__.py`, `ports.py`, `env.py`, `file.py`, `factory.py`, `verify.py`
- Test: `tests/test_secret_provider.py`, `tests/test_verify_secrets.py`

**Interfaces:**
- Produces:
  - `Settings` new fields: `require_strong_secrets: bool = False`, `secret_provider: Literal["env","file"] = "env"`, `secret_dir: Path = Path("secrets")`, `audit_signing_key: str = "dev-audit-signing-key-change-me-not-for-production"`, `audit_encryption_key: str = ""`, `cipher: Literal["none","fernet"] = "none"`, `db_sslmode: str = ""`, `minio_secure: bool = False`, `require_https: bool = False`.
  - `secret.ports.SecretError(Exception)`; `SecretProvider` Protocol: `get(name: str) -> str | None`, `require(name: str) -> str`.
  - `secret.env.EnvSecretProvider(settings: Settings)`; `secret.file.FileSecretProvider(directory: Path)`.
  - `secret.factory.make_secret_provider(settings: Settings) -> SecretProvider`.
  - `secret.verify.PLACEHOLDERS: frozenset[str]`; `redact(text: str, secrets: Iterable[str]) -> str`; `verify_secrets(settings: Settings, provider: SecretProvider) -> None`.

- [ ] **Step 1: Write failing tests** in `tests/test_secret_provider.py`:
```python
def test_env_provider_returns_configured_secret():
    s = Settings(minio_secret_key="s3kr3t-value-1234")
    assert EnvSecretProvider(s).get("minio_secret_key") == "s3kr3t-value-1234"

def test_env_provider_require_raises_on_empty():
    with pytest.raises(SecretError):
        EnvSecretProvider(Settings(audit_encryption_key="")).require("audit_encryption_key")

def test_file_provider_reads_and_missing_is_none(tmp_path):
    (tmp_path / "audit_signing_key").write_text("file-key-value-123456\n")
    p = FileSecretProvider(tmp_path)
    assert p.get("audit_signing_key") == "file-key-value-123456"
    assert p.get("absent") is None
```
And in `tests/test_verify_secrets.py`:
```python
def test_verify_secrets_noop_in_dev():
    verify_secrets(Settings(), make_secret_provider(Settings()))  # no raise

def test_verify_secrets_raises_on_placeholder_audit_key_in_prod():
    s = Settings(require_strong_secrets=True)  # audit_signing_key is the dev placeholder
    with pytest.raises(SecretError):
        verify_secrets(s, make_secret_provider(s))

def test_verify_secrets_message_names_setting_not_value():
    s = Settings(require_strong_secrets=True)
    try:
        verify_secrets(s, make_secret_provider(s))
    except SecretError as exc:
        assert s.audit_signing_key not in str(exc)
        assert "audit_signing_key" in str(exc)

def test_verify_secrets_skips_inactive_backend():
    # db_url is the sair:sair placeholder but pgvector is OFF → ignored
    s = Settings(require_strong_secrets=True, audit_signing_key="x" * 32, auth_dev_secret="y" * 32)
    verify_secrets(s, make_secret_provider(s))  # no raise

def test_verify_secrets_checks_db_url_when_pgvector():
    s = Settings(require_strong_secrets=True, vector_store="pgvector",
                 audit_signing_key="x" * 32, auth_dev_secret="y" * 32)
    with pytest.raises(SecretError):
        verify_secrets(s, make_secret_provider(s))

def test_verify_secrets_overrides_auth_allow_dev_secret():
    s = Settings(require_strong_secrets=True, auth_allow_dev_secret=True, audit_signing_key="x" * 32)
    with pytest.raises(SecretError):  # prod refuses the dev auth secret despite the opt-in
        verify_secrets(s, make_secret_provider(s))

def test_redact_replaces_known_secret():
    assert "s3kr3t" not in redact("token=s3kr3t end", ["s3kr3t"])
```

- [ ] **Step 2: Run the tests, verify they fail** (import errors / missing fields). Run: `./.venv/bin/pytest -q tests/test_secret_provider.py tests/test_verify_secrets.py`. Expected: FAIL.

- [ ] **Step 3: Add the Slice-5 fields** to `Settings` in `config.py` (after the OIDC block, line 84), with the defaults in the Interfaces block and a one-line `# --- Secret mgmt / encryption / transit (Slice 5) ---` comment.

- [ ] **Step 4: Implement `secret/`.** `ports.py` (Protocol + `SecretError`); `env.py` (`EnvSecretProvider` with an explicit `_NAME_TO_ATTR` dict mapping `{"db_url","minio_access_key","minio_secret_key","auth_dev_secret","audit_signing_key","audit_encryption_key"}` to the same-named `Settings` attribute — `get` returns the attr or `None` for an unknown name; `require` raises `SecretError` when unset/empty); `file.py` (`get` reads `directory/<name>` stripped, `None` if missing; `require` raises if missing/empty); `factory.py` (`make_secret_provider`: `env` default, `file` → `FileSecretProvider(settings.secret_dir)`); `verify.py` (`PLACEHOLDERS` = the dev defaults `{"sair:sair@","minioadmin","dev-insecure-change-me-not-for-production","dev-audit-signing-key-change-me-not-for-production"}`; `redact`; `verify_secrets`). `verify_secrets`: return immediately unless `require_strong_secrets`; a secret is weak if it contains a `PLACEHOLDERS` member or `len < 16`; always check `auth_dev_secret` + `audit_signing_key`; check `db_url` only if `vector_store=="pgvector"`, `minio_access_key`/`minio_secret_key` only if `object_store=="minio"`, `audit_encryption_key` only if `cipher=="fernet"`; raise `SecretError(f"{setting} is a placeholder or too weak for production; set a strong SAIR_{SETTING.upper()}")`.

- [ ] **Step 5: Run the tests, verify they pass.** Run: `./.venv/bin/pytest -q tests/test_secret_provider.py tests/test_verify_secrets.py`. Expected: PASS.

- [ ] **Step 6: Commit.** `git add -A && git commit -m "feat(secret): SecretProvider seam + fail-closed-prod verify_secrets (Slice 5 Task 1)"`

---

### Task 2: At-rest cipher seam (`crypto/`) + `[crypto]` extra

**Files:**
- Create: `src/secure_ai_research/crypto/__init__.py`, `ports.py`, `null.py`, `fernet.py`, `factory.py`
- Modify: `pyproject.toml` (add `[crypto]` extra after the `oidc` extra, line 48)
- Test: `tests/test_crypto_cipher.py`

**Interfaces:**
- Consumes: `secret.ports.SecretProvider` (Task 1).
- Produces: `crypto.ports.CipherError(Exception)`; `Cipher` Protocol `encrypt(data: bytes) -> bytes` / `decrypt(token: bytes) -> bytes`; `crypto.null.NullCipher`; `crypto.fernet.FernetCipher(key: str)`; `crypto.factory.make_cipher(settings: Settings, provider: SecretProvider) -> Cipher`.

- [ ] **Step 1: Write failing tests** in `tests/test_crypto_cipher.py`:
```python
def test_null_cipher_is_identity():
    c = NullCipher()
    assert c.decrypt(c.encrypt(b"audit line")) == b"audit line"

def test_make_cipher_default_is_null():
    assert isinstance(make_cipher(Settings(), make_secret_provider(Settings())), NullCipher)

def test_fernet_bad_key_or_missing_extra_raises_cipher_error():
    with pytest.raises(CipherError):   # missing [crypto] → extra error; present → invalid-key error
        FernetCipher("not-a-valid-fernet-key")

def test_fernet_error_message_has_no_key():
    try:
        FernetCipher("not-a-valid-fernet-key-SECRET123")
    except CipherError as exc:
        assert "SECRET123" not in str(exc)

def test_cryptography_not_imported_on_default_path():
    import sys, importlib
    importlib.import_module("secure_ai_research.crypto.factory")
    make_cipher(Settings(), make_secret_provider(Settings()))
    assert "cryptography" not in sys.modules
```
Integration test (same file, marked `@pytest.mark.integration`):
```python
@pytest.mark.integration
def test_fernet_round_trip():
    pytest.importorskip("cryptography")
    from cryptography.fernet import Fernet
    c = FernetCipher(Fernet.generate_key().decode())
    assert c.decrypt(c.encrypt(b"secret audit line")) == b"secret audit line"
```

- [ ] **Step 2: Run the tests, verify they fail.** Run: `./.venv/bin/pytest -q tests/test_crypto_cipher.py`. Expected: FAIL (import errors). Confirm the integration test is deselected under the default marker.

- [ ] **Step 3: Implement `crypto/`.** `ports.py` (Protocol + `CipherError`); `null.py` (`NullCipher.encrypt/decrypt` return input); `fernet.py` (`FernetCipher.__init__` does `try: from cryptography.fernet import Fernet except ImportError → CipherError("cipher 'fernet' requires the [crypto] extra: pip install -e '.[crypto]'")`, then `try: self._f = Fernet(key.encode()) except Exception → CipherError("invalid Fernet key")` — never echo the key; `encrypt`/`decrypt` wrap `self._f`, mapping any decrypt failure to `CipherError("decrypt failed")`); `factory.py` (`make_cipher`: `fernet` → `FernetCipher(provider.require("audit_encryption_key"))`, else `NullCipher()`).

- [ ] **Step 4: Add the `[crypto]` extra** to `pyproject.toml` after the `oidc` extra, with the same comment pattern (opt-in, hermetic suite never imports it): `crypto = ["cryptography>=43,<47"]`.

- [ ] **Step 5: Run the tests, verify they pass.** Run: `./.venv/bin/pytest -q tests/test_crypto_cipher.py`. Expected: PASS (integration test deselected).

- [ ] **Step 6: Commit.** `git add -A && git commit -m "feat(crypto): Cipher seam (NullCipher default, opt-in FernetCipher behind [crypto]) (Slice 5 Task 2)"`

---

### Task 3: Tamper-evident audit — `audit/signing.py` + `record.py` rewire + service call sites

**Files:**
- Create: `src/secure_ai_research/audit/signing.py`
- Modify: `src/secure_ai_research/audit/record.py` (rewrite `emit`/`read_records`, add imports)
- Modify: `src/secure_ai_research/research_service.py` (ctor + 5 `emit` sites + `_emit_terminal` guard)
- Test: `tests/test_audit_signing.py` (+ keep the whole suite green)

**Interfaces:**
- Consumes: `crypto.null.NullCipher`, `crypto.ports.Cipher` (Task 2); `audit.record.ResearchRecord` (existing).
- Produces:
  - `audit.signing`: `GENESIS_HASH = "0"*64`; `DEV_AUDIT_KEY` (== the `audit_signing_key` default string); `AuditEnvelope(BaseModel)` fields `seq:int, prev_hash:str, record_hash:str, hmac:str, record:ResearchRecord`; `AuditFormatError(ValueError)`; `canonical_record_bytes(record) -> bytes`; `compute_record_hash(seq:int, prev_hash:str, record) -> str`; `compute_hmac(record_hash:str, key:str) -> str`; `seal(seq:int, prev_hash:str, record, key:str) -> AuditEnvelope`; `parse_chain_head(lines: list[bytes], cipher: Cipher) -> tuple[int, str]`; `ChainVerification(BaseModel)` fields `ok:bool, count:int, first_bad_seq:int|None=None, reason:str=""`; `verify_chain(path: Path, key: str, *, cipher: Cipher | None = None) -> ChainVerification`.
  - `audit.record.emit(record, path, *, key: str, cipher: Cipher | None = None) -> None`; `read_records(path, *, cipher: Cipher | None = None) -> list[ResearchRecord]`.
  - `research_service.ResearchService.__init__` gains keyword-only `audit_key: str = DEV_AUDIT_KEY`, `audit_cipher: Cipher | None = None`.

- [ ] **Step 1: Write failing tests** in `tests/test_audit_signing.py` (use a helper `_rec(**kw)` building a minimal `ResearchRecord`, and a fixed test key `K = "test-signing-key-0123456789"`):
```python
def test_emit_then_read_returns_research_record(tmp_path):
    p = tmp_path / "a.jsonl"
    r = _rec(objective="o")
    emit(r, p, key=K)
    assert read_records(p) == [r]

def test_emitted_chain_verifies(tmp_path):
    p = tmp_path / "a.jsonl"
    for i in range(3):
        emit(_rec(objective=f"o{i}"), p, key=K)
    v = verify_chain(p, K)
    assert v.ok and v.count == 3

def test_tampered_record_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    for i in range(3):
        emit(_rec(objective=f"o{i}"), p, key=K)
    lines = p.read_bytes().splitlines()
    env = json.loads(lines[1]); env["record"]["objective"] = "EVIL"
    lines[1] = json.dumps(env).encode(); p.write_bytes(b"\n".join(lines) + b"\n")
    v = verify_chain(p, K)
    assert not v.ok and v.first_bad_seq == 1

def test_reordered_records_detected(tmp_path):
    # swap lines 0 and 1 → broken prev_hash / seq
    ...
    assert not verify_chain(p, K).ok

def test_flipped_hmac_detected(tmp_path):
    # mutate one hex char of line 0's "hmac" → compare_digest fails
    ...
    assert not verify_chain(p, K).ok

def test_tail_truncation_not_detected(tmp_path):
    # drop the last of 3 lines → prefix is still a valid chain (honest limitation)
    ...
    v = verify_chain(p, K)
    assert v.ok and v.count == 2

def test_wrong_key_fails_verification(tmp_path):
    emit(_rec(), p, key=K)
    assert not verify_chain(p, "other-key-0123456789abcd").ok

def test_canonical_record_bytes_idempotent():
    r = _rec(timestamp=datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC),
             objective="übér", tool_invocations=[{"score": 0.5}])
    assert canonical_record_bytes(r) == canonical_record_bytes(
        ResearchRecord.model_validate(r.model_dump(mode="json")))

def test_chain_head_rejects_incompatible_line():
    with pytest.raises(AuditFormatError):
        parse_chain_head([_rec().model_dump_json().encode()], NullCipher())

def test_read_records_tolerates_legacy_bare_line(tmp_path):
    p = tmp_path / "a.jsonl"; r = _rec()
    p.write_bytes(r.model_dump_json().encode() + b"\n")
    assert read_records(p) == [r]

def test_dev_audit_key_matches_config_default():
    assert Settings().audit_signing_key == DEV_AUDIT_KEY
```

- [ ] **Step 2: Run the tests, verify they fail.** Run: `./.venv/bin/pytest -q tests/test_audit_signing.py`. Expected: FAIL.

- [ ] **Step 3: Implement `audit/signing.py`.** `canonical_record_bytes` = `json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")`. `compute_record_hash` = `sha256(f"{seq}\n{prev_hash}\n".encode() + canonical_record_bytes(record)).hexdigest()`. `compute_hmac` = `hmac.new(key.encode(), record_hash.encode(), hashlib.sha256).hexdigest()`. `seal` composes them. `parse_chain_head`: no non-empty line → `(-1, GENESIS_HASH)`; else decrypt the last non-empty line and parse `AuditEnvelope` → `(env.seq, env.record_hash)`, mapping any parse/validation/cipher failure to `AuditFormatError` (no silent fork). `verify_chain`: `cipher = cipher or NullCipher()`; iterate lines in order, for index `i` decrypt+parse the envelope (failure → `ok=False, first_bad_seq=i, reason`), then check `seq==i`, `prev_hash == (GENESIS_HASH if i==0 else prev.record_hash)`, recomputed `record_hash` matches, and `hmac.compare_digest(compute_hmac(record_hash,key), env.hmac)`; first failure returns with `first_bad_seq`; all pass → `ok=True, count=n`.

- [ ] **Step 4: Rewrite `audit/record.py`.** Add imports (`fcntl`, `threading`, `NullCipher`, signing helpers); module `_LOCK = threading.Lock()`. `emit(record, path, *, key, cipher=None)`: `cipher = cipher or NullCipher()`; mkdir parents; under `_LOCK`, open `path` in binary append+read (`"a+b"`), `fcntl.flock(f, fcntl.LOCK_EX)`, `f.seek(0)`, read + `splitlines()`, `seq0, prev = parse_chain_head(lines, cipher)`, `env = seal(seq0+1, prev, record, key)`, write `cipher.encrypt(env.model_dump_json().encode("utf-8")) + b"\n"` at end, flush (flock released on close). `read_records(path, *, cipher=None)`: `cipher = cipher or NullCipher()`; absent → `[]`; for each non-empty line, `dec = cipher.decrypt(raw)`, try `AuditEnvelope.model_validate_json(dec)` → append `.record`, on failure fall back to `ResearchRecord.model_validate_json(dec)` (legacy tolerance).

- [ ] **Step 5: Rewire `research_service.py` (additive only).** Ctor: add keyword-only `audit_key: str = DEV_AUDIT_KEY` and `audit_cipher: Cipher | None = None`; set `self._audit_key = audit_key` and `self._audit_cipher = audit_cipher or NullCipher()`; import `DEV_AUDIT_KEY` from `audit.signing`, `Cipher`/`NullCipher` from `crypto`. Change each of the **5** `emit(...)` call sites (lines ~365, ~463, ~548, ~605, and `_emit_terminal` ~616) to pass `key=self._audit_key, cipher=self._audit_cipher`. In `_emit_terminal`, wrap the `emit(...)` in `try/except Exception as exc:` logging `logging.getLogger("secure_ai_research.audit").error("terminal audit emit failed: %s", type(exc).__name__)` (type only — no payload; the fault-path emitter must never raise a second exception).

- [ ] **Step 6: Run the task tests, verify they pass.** Run: `./.venv/bin/pytest -q tests/test_audit_signing.py`. Expected: PASS.

- [ ] **Step 7: Run the FULL hermetic suite and fix any audit-format-sensitive test.** Run: `./.venv/bin/pytest -q -m "not integration"` (redirect to a workspace file, read the tail). Expected: PASS. Any failure is a test that asserted the *old* bare-record file bytes; migrate it to read via `read_records` / `verify_chain` (the record content is unchanged). Confirm `tests/test_eval_regression_gate.py` is green (the Phase-4 1.0 / 0.7742 gate is unaffected — it reads pipeline results, not audit bytes).

- [ ] **Step 8: Commit.** `git add -A && git commit -m "feat(audit): tamper-evident signed hash-chain, default-on; read_records unchanged (Slice 5 Task 3)"`

---

### Task 4: In-transit posture — `transit.py` + DSN/MinIO TLS knobs + docs

**Files:**
- Create: `src/secure_ai_research/transit.py`
- Modify: `src/secure_ai_research/retrieval/factory.py` (apply `db_sslmode`), `src/secure_ai_research/storage/factory.py` (pass `minio_secure`)
- Create: `docs/phase5-encryption-transit.md`
- Test: `tests/test_transit.py`

**Interfaces:**
- Consumes: `Settings` (Task 1 transit fields).
- Produces: `transit.apply_sslmode(db_url: str, sslmode: str) -> str`; `transit.check_transit_posture(settings: Settings) -> list[str]`.

- [ ] **Step 1: Write failing tests** in `tests/test_transit.py`:
```python
def test_loopback_posture_has_no_warnings():
    assert check_transit_posture(Settings()) == []

def test_non_loopback_pgvector_without_ssl_warns():
    s = Settings(vector_store="pgvector", db_url="postgresql://u:p@db.example.com:5432/x")
    assert any("sslmode" in w or "pgvector" in w.lower() for w in check_transit_posture(s))

def test_sslmode_require_clears_pgvector_warning():
    s = Settings(vector_store="pgvector", db_url="postgresql://u:p@db.example.com:5432/x",
                 db_sslmode="require")
    assert check_transit_posture(s) == []

def test_non_loopback_minio_without_tls_warns():
    s = Settings(object_store="minio", minio_endpoint="minio.example.com:9000", minio_secure=False)
    assert check_transit_posture(s) != []

def test_apply_sslmode_appends_when_absent_and_preserves_when_present():
    assert apply_sslmode("postgresql://u:p@h/x", "require").endswith("sslmode=require")
    assert apply_sslmode("postgresql://u:p@h/x?sslmode=verify-full", "require").count("sslmode") == 1
```

- [ ] **Step 2: Run the tests, verify they fail.** Run: `./.venv/bin/pytest -q tests/test_transit.py`. Expected: FAIL.

- [ ] **Step 3: Implement `transit.py`.** `_is_loopback(host)` → `host in {"localhost","127.0.0.1","::1",""}`. `check_transit_posture`: parse `db_url` host via `urllib.parse.urlsplit`, `minio_endpoint` host via `split(":")[0]`, `oidc_issuer` via `urlsplit`; append a one-line warning for each ACTIVE, non-loopback endpoint lacking TLS — pgvector active and `"sslmode=require" not in db_url and db_sslmode != "require"`; minio active and not `minio_secure`; `auth=="oidc"` and issuer scheme is `http`. `apply_sslmode(db_url, sslmode)`: if `sslmode` falsy or `"sslmode="` already in `db_url`, return unchanged; else append `("&" if "?" in db_url else "?") + f"sslmode={sslmode}"`.

- [ ] **Step 4: Apply the knobs in the factories.** In `retrieval/factory.py` `make_vector_store`, when building the pgvector DSN, pass it through `apply_sslmode(settings.db_url, settings.db_sslmode)`. In `storage/factory.py` `make_object_store`, pass `secure=settings.minio_secure` to the MinIO client constructor. (Read each factory first; these are additive one-liners on the opt-in branch — the default `memory` path is untouched.)

- [ ] **Step 5: Write `docs/phase5-encryption-transit.md`** — the TLS boundary (uvicorn / reverse proxy owns client↔app TLS), how to enable each knob (`SAIR_DB_SSLMODE`, `SAIR_MINIO_SECURE`, `SAIR_REQUIRE_HTTPS`), the loopback-bound dev posture (all compose ports on `127.0.0.1`), the **one-key-per-audit-log** rule, and the honest WORM/at-rest limitations from spec §9.

- [ ] **Step 6: Run the tests + full hermetic suite, verify they pass.** Run: `./.venv/bin/pytest -q tests/test_transit.py && ./.venv/bin/pytest -q -m "not integration"`. Expected: PASS.

- [ ] **Step 7: Commit.** `git add -A && git commit -m "feat(transit): in-transit posture check + TLS knobs + docs (Slice 5 Task 4)"`

---

### Task 5: Wiring + startup gate (`deps` + `main` lifespan)

**Files:**
- Modify: `src/secure_ai_research/api/deps.py` (`get_service` resolves key/cipher from the secret provider)
- Modify: `src/secure_ai_research/api/main.py` (add a lifespan: `verify_secrets` + transit enforcement + eager `get_service` + prod-only log-head `verify_chain`)
- Test: `tests/test_startup_gate.py`

**Interfaces:**
- Consumes: `make_secret_provider`, `verify_secrets` (T1); `make_cipher` (T2); `verify_chain` (T3); `check_transit_posture` (T4); `get_service` (existing).
- Produces: a `lifespan(app)` async context manager on `main.app`; `get_service` now builds the service with `audit_key=provider.require("audit_signing_key")`, `audit_cipher=make_cipher(settings, provider)`.

- [ ] **Step 1: Write failing tests** in `tests/test_startup_gate.py`:
```python
def test_startup_dev_is_noop():
    get_settings.cache_clear(); get_service.cache_clear()
    with TestClient(app) as c:                      # runs the lifespan
        assert c.get("/health").status_code == 200

def test_startup_prod_weak_secret_refuses_boot(monkeypatch):
    monkeypatch.setenv("SAIR_REQUIRE_STRONG_SECRETS", "true")  # audit key still the placeholder
    get_settings.cache_clear(); get_service.cache_clear()
    with pytest.raises(Exception):                 # lifespan raises → context-enter fails
        with TestClient(app):
            pass
    get_settings.cache_clear(); get_service.cache_clear()

def test_service_from_deps_writes_verifiable_signed_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("SAIR_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SAIR_AUDIT_SIGNING_KEY", "wired-key-0123456789abcd")
    get_settings.cache_clear(); get_service.cache_clear()
    svc = get_service()
    svc.research_cve("CVE-2099-0001", role="senior_analyst")
    v = verify_chain(tmp_path / "audit.jsonl", "wired-key-0123456789abcd")
    assert v.ok and v.count >= 1
    get_settings.cache_clear(); get_service.cache_clear()
```

- [ ] **Step 2: Run the tests, verify they fail.** Run: `./.venv/bin/pytest -q tests/test_startup_gate.py`. Expected: FAIL.

- [ ] **Step 3: Wire `deps.get_service`.** After `settings = get_settings()`, build `provider = make_secret_provider(settings)`; pass `audit_key=provider.require("audit_signing_key")` and `audit_cipher=make_cipher(settings, provider)` into the `ResearchService(...)` construction (additive keyword args; everything else unchanged).

- [ ] **Step 4: Add the lifespan to `main.py`.** An `@asynccontextmanager async def lifespan(app)` that: reads `get_settings()`, builds the provider, calls `verify_secrets(settings, provider)` (fail-closed prod), computes `check_transit_posture(settings)` and raises `RuntimeError` if warnings AND (`require_https` or `require_strong_secrets`), eagerly calls `get_service()` (misconfig → boot failure), and — **only when `require_strong_secrets`** — runs `verify_chain(settings.audit_log_path, provider.require("audit_signing_key"), cipher=make_cipher(settings, provider))` and raises `RuntimeError` if `not ok` (prod refuses to start on a broken/legacy log; dev skips this so a `with TestClient` never couples to the on-disk log). Pass `lifespan=lifespan` to `FastAPI(...)`.

- [ ] **Step 5: Run the task tests, verify they pass.** Run: `./.venv/bin/pytest -q tests/test_startup_gate.py`. Expected: PASS.

- [ ] **Step 6: Run the FULL hermetic suite.** Run: `./.venv/bin/pytest -q -m "not integration"` (redirect + tail). Expected: PASS, including the Phase-4 regression gate. Fix any `with TestClient(app)` test that now trips the dev lifespan (should be none — dev is a no-op).

- [ ] **Step 7: Commit.** `git add -A && git commit -m "feat(startup): fail-closed-prod lifespan gate + deps signs audit with managed key (Slice 5 Task 5)"`
