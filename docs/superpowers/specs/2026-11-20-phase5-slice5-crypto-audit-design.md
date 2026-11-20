# Phase 5 Slice 5 — Encryption, Secret Management & Tamper-Evident Audit (ROADMAP Week 18)

**Status:** design, pending approval · **Date:** 2026-11-20 · **Repo:** local, no remote
**Prev:** Slice 4 (OIDC/Keycloak identity) merged `main@117def9`

## 1. Intent & why

ROADMAP Week 18 is the compliance-hardening slice: **encryption at rest/in transit, secret
management, and audit WORM/signing.** The platform already writes an append-only JSONL audit
trail (`audit/record.py`) and sources secrets from `SAIR_*` env vars, but nothing today makes
the trail *tamper-evident*, nothing stops a weak/placeholder secret reaching production, and no
data is encrypted. This slice adds those controls so the platform can honestly claim NIST
800-53 **AU-9 (Protection of Audit Information)**, **AU-10 (Non-repudiation)**, **IA-5
(Authenticator/Secret Management)**, **SC-28 (Protection at Rest)**, and **SC-8 (Protection in
Transit)** — as *demonstrated, tested controls*, not aspirational prose. The data is
PUBLIC/synthetic, so these are control demonstrations on a realistic surface, not protection of
real classified data (stated plainly in the SSP next slice).

Chris chose **all four sub-areas in one slice**, and chose **audit signing ON by default**
(fail-closed only in prod mode), matching the Slice-4 precedent where the control (HS256
verification) is the default path rather than an opt-in flag.

## 2. Goals / Non-goals / Anti-goals

**Goals**
- Audit trail is **tamper-evident**: any edit, reorder, insertion, or mid-stream deletion of a
  past record is detected by a `verify_chain()` that pinpoints the first bad sequence number.
- A **secret-management seam** centralizes secret sourcing and **fails closed in prod mode** on
  placeholder/weak secrets (DB, MinIO, auth, audit-signing); secrets never leak into audit
  records, error messages, or logs.
- An **encryption-at-rest seam** can encrypt the audit log (default off = plaintext; opt-in
  Fernet behind a new `[crypto]` extra), composed as sign-then-encrypt.
- An **in-transit posture**: config knobs (`db_sslmode`, `minio_secure`, `require_https`), a
  startup check that flags a non-loopback endpoint without TLS, and documentation.

**Non-goals**
- True OS/storage-enforced WORM (append-only file attrs, S3 Object Lock) — that is deployment,
  documented but not coded here.
- Encrypting PUBLIC corpus data (NVD cache, pgvector rows, MinIO objects) for confidentiality —
  the cipher seam is built and demonstrated on the audit log; wiring it to those backends is a
  follow-on, noted but not required.
- Asymmetric audit signatures (Ed25519), external timestamp/anchor services, HSM/KMS.
- Changing the deterministic **pipeline output** (answers, citations, eval metrics): the
  Phase-4 `grounding=1.0 / citation 0.7742` CI gate must stay green and byte-identical.

**Anti-goals (failure even if it "works")**
- The app refusing to start in the default dev config because of a fail-closed secret gate
  (fail-closed must bite **only** in explicit prod mode).
- Over-claiming: calling tamper-*evidence* "WORM", or claiming tail-truncation is detected when
  it is not without an external anchor. Honest scope is a hard requirement.
- A signing/secret fault turning into an unhandled 500 with zero audit records (same invariant
  defended in every prior slice).

## 3. Constraints (posture)

- **Default path byte-identical for pipeline output**; deterministic/offline/stdlib by default.
- Real crypto dependency (`cryptography`) is **opt-in behind a seam + a new `[crypto]` extra**;
  the hermetic suite never imports it (mirrors pgvector/minio/oidc). The default cipher is a
  pure-stdlib identity `NullCipher`.
- **Audit signing is stdlib-only** (`hmac`/`hashlib`): it is a *default-on* control, so it must
  not need any non-stdlib dependency and must work offline with a dev key.
- One audit record per request; fail-closed faults → `FETCH_ERROR`/startup-refusal, never an
  unhandled 500.
- Do not modify pipeline-semantics modules (`retrieval/authz.py`, `research_service.py` logic)
  beyond the minimal, additive audit-emission wiring described in §5.2.

## 4. Approaches considered

**Scope.** (a) Split Week 18 into focused sub-slices (audit-signing first) vs **(b) all four in
one slice.** Chris chose (b). The design sequences the work so the secret seam lands before the
audit signer that consumes its key.

**Audit signing rollout.** (a) **Default-on, fail-closed in prod** (chosen) vs (b) opt-in flag.
Default-on gives a real AU-9 control and matches Slice 4; its cost is an audit **file-format**
change (signed envelope) and a small test migration, bounded by keeping `read_records()`
returning `ResearchRecord` so in-memory consumers are unaffected.

**Signing primitive.** (a) **HMAC-SHA256 hash-chain** (chosen, stdlib) vs (b) Ed25519
asymmetric (needs `cryptography`, non-repudiation against the log owner). HMAC keeps the
default-on control stdlib-only; Ed25519 is a documented future upgrade. We add a **keyless
SHA-256 hash-chain** underneath the HMAC so integrity (detect accidental/unprivileged edits) is
present even before any key, and **authenticity** (HMAC) is layered using the managed key.

**Secret sourcing.** (a) **`SecretProvider` seam, env default + opt-in file** (chosen) vs (b)
direct `pydantic-settings` only (status quo, no fail-closed gate) vs (c) a real vault client
(out of posture). The seam lets a deployment move secrets off env vars without code change and
gives one place for the fail-closed gate + redaction.

**At-rest cipher.** (a) **`Cipher` seam, `NullCipher` default + opt-in `FernetCipher`** (chosen)
vs (b) always-encrypt (breaks offline/stdlib default; no stdlib AES) vs (c) rely on
filesystem/DB encryption only (deployment, not demonstrable in tests). Fernet (AES-128-CBC +
HMAC authentication, from `cryptography`) is a well-reviewed authenticated cipher; the seam
keeps the default plaintext and the dependency opt-in.

**In-transit.** (a) **Config knobs + startup posture check + docs** (chosen) vs (b) terminate
TLS in-process (wrong layer; uvicorn/reverse-proxy own it) vs (c) docs only (misses an
enforceable check). Minimal code, honest about the deployment boundary.

## 5. Design

Four subsystems. New packages `secret/` and `crypto/`; `audit/` extended. Build order =
secret → audit-signing → cipher/at-rest → in-transit.

### 5.1 Secret management — `secret/` package

> Named `secret/` (singular) to avoid shadowing the stdlib `secrets` module.

- **`secret/ports.py`**: `SecretProvider` Protocol
  - `get(name: str) -> str | None` — resolved secret or None if unset.
  - `require(name: str) -> str` — resolved secret, or raise `SecretError` if unset/empty.
  - `SecretError(Exception)` — config/availability fault (startup-time; never carries the
    secret value).
- **`secret/env.py`**: `EnvSecretProvider(settings)` — reads from the already-parsed `Settings`
  (today's behavior); `get("db_password")` → `settings.db_password`, etc., via an explicit
  name→attribute map (no `getattr` on arbitrary input). Default provider ⇒ byte-identical
  behavior.
- **`secret/file.py`**: `FileSecretProvider(dir: Path)` — reads `dir/<name>` files
  (Docker-/systemd-style secrets), stripped; missing file → None. Opt-in only.
- **`secret/factory.py`**: `make_secret_provider(settings) -> SecretProvider` — `env` default,
  `file` when `SAIR_SECRET_PROVIDER=file`.
- **`secret/verify.py`**:
  - `PLACEHOLDERS: frozenset[str]` — the known dev placeholders (`"minioadmin"`,
    `"dev-insecure-change-me-not-for-production"`, the audit dev key, `"sair"` db password).
  - `redact(text: str, secrets: Iterable[str]) -> str` — replaces any secret substring with
    `"***"`; used nowhere in the hot path by default but available for error construction.
  - `verify_secrets(settings, provider) -> None` — **the fail-closed gate.** When
    `settings.require_strong_secrets` is True (prod mode), raises `SecretError` (naming the
    setting, never the value) if any **active** managed secret is a placeholder or shorter than
    16 chars. The managed set is `auth_dev_secret` and `audit_signing_key` (always active), plus
    `db_url` (checked **only** when `vector_store=pgvector` — the placeholder is the compose
    default `sair:sair@` credential embedded in the DSN) and `minio_access_key`/`minio_secret_key`
    (checked **only** when `object_store=minio` — placeholder `minioadmin`). There is **no**
    `db_password` field (builder-check Q6): the DB credential lives inside `db_url`. In prod mode
    `require_strong_secrets` **overrides** `auth_allow_dev_secret` — a prod deployment refuses a
    dev auth secret regardless of that opt-in (the stricter reading; **builder-check call,
    flagged for Chris**). Default (dev) ⇒ no-op, so the app runs on dev placeholders. Run once at
    startup via the lifespan (§5.5), so a refusal is a clean boot failure, not a per-request 500.
  - Auth already self-gates via `make_identity_provider` (Slice 4); `verify_secrets` is the
    unified superset and is additive (does not change the auth factory).

### 5.2 Audit WORM/signing — `audit/` extended

**Format — a signing envelope around each record (not inside `ResearchRecord`).** Each audit
line becomes:

```json
{"seq":0,"prev_hash":"0000…(64)","record_hash":"<sha256 hex>","hmac":"<hmac-sha256 hex>","record":{…ResearchRecord…}}
```

- **`audit/signing.py`** (new, stdlib only):
  - `GENESIS_HASH = "0" * 64`.
  - `AuditEnvelope(BaseModel)`: `seq:int`, `prev_hash:str`, `record_hash:str`, `hmac:str`,
    `record:ResearchRecord`.
  - `canonical_record_bytes(record: ResearchRecord) -> bytes` =
    `json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",",":"),
    ensure_ascii=False).encode()` — canonical, field-order-independent (mirrors the document-hash
    pattern across loaders). **Must be round-trip idempotent (builder-check Q7):**
    `canonical_record_bytes(r) == canonical_record_bytes(ResearchRecord.model_validate(r.model_dump(mode="json")))`,
    because `verify_chain` re-derives the hash from the *parsed* envelope. `mode="json"` is used
    on both seal and verify sides and `ensure_ascii` is pinned; the datetime/float/unicode
    round-trip is pinned by Review Focus 7. If idempotency can't be met, the fallback is to store
    the record as a raw canonical JSON **string** in the envelope and hash that exact stored
    string (no re-serialization at verify).
  - `compute_record_hash(seq, prev_hash, record) -> str` =
    `sha256(f"{seq}\n{prev_hash}\n".encode() + canonical_record_bytes(record)).hexdigest()` —
    binds position + previous link + content (keyless integrity).
  - `compute_hmac(record_hash, key) -> str` =
    `hmac.new(key.encode(), record_hash.encode(), sha256).hexdigest()` (authenticity).
  - `seal(seq, prev_hash, record, key) -> AuditEnvelope` — builds a full link.
  - `verify_chain(path, key, *, cipher=NullCipher()) -> ChainVerification` where
    `ChainVerification(BaseModel)` = `ok:bool`, `count:int`, `first_bad_seq:int|None`,
    `reason:str`. Recomputes, for every line in order: `seq` is monotonic from 0, `prev_hash`
    equals the previous `record_hash` (first = `GENESIS_HASH`), `record_hash` recomputes,
    `hmac` recomputes via `hmac.compare_digest`. First failure sets `ok=False`, `first_bad_seq`,
    and a non-sensitive `reason` (e.g. `"hmac mismatch"`, `"broken prev_hash link"`).

- **`audit/record.py`** (modified, backward-compatible API shape):
  - `DEV_AUDIT_KEY = "dev-audit-key-change-me-not-for-production"` (placeholder; listed in
    `secret/verify.PLACEHOLDERS`).
  - `emit(record, path, *, key, cipher=NullCipher()) -> None` — the write critical section is
    serialized by **`fcntl.flock(LOCK_EX)` on the audit file** (cross-process, for a multi-worker
    deployment) **inside a module `threading.Lock`** (intra-process). Under the lock: read the
    chain head `(last_seq, last_record_hash)` from the file's last non-empty line (decrypt+parse
    envelope); `seq = last_seq + 1`; `prev_hash = last_record_hash`; `seal(...)`; write
    `cipher.encrypt(envelope.model_dump_json().encode()) + b"\n"`. (NullCipher ⇒ plaintext
    signed JSON line, newline-framed and human-readable; Fernet ⇒ one base64 token per line.)
    **No-silent-fork policy (builder-check Q2/Q3):** `emit` appends only to an **empty** file or
    one whose head is a compatible envelope (same cipher/key family). An **undecryptable or
    non-envelope head is never treated as genesis** — that would silently fork the chain. Startup
    validation (§5.5) refuses an incompatible existing log at boot, so a running writer always
    sees a clean head. `read_records` still tolerates bare legacy `ResearchRecord` lines for
    *viewing*, but `emit`/`verify_chain` operate on the signed envelope format only.
  - **One key per log file (builder-check Q4):** a single audit file must be written with one
    key+cipher; mixing the API's managed key and a CLI dev key in one file makes `verify_chain`
    (correctly) fail at the first foreign record. The API writes `settings.audit_log_path`; the
    offline tools write their own paths (below). This is documented, not enforced in code.
  - `read_records(path, *, cipher=NullCipher()) -> list[ResearchRecord]` — decrypt each line,
    parse as `AuditEnvelope` and return `env.record`; a line that is a bare legacy
    `ResearchRecord` (no envelope) is still accepted (robustness). **Return type unchanged ⇒
    every existing in-memory consumer/test is unaffected.**
  - `_chain_head(path, cipher)` helper reads the whole file and returns the last line's
    `(seq, record_hash)` — O(n), acceptable at this slice's volume (deferred optimization:
    reverse-seek the last line, or an in-memory stateful emitter).

- **`research_service.py` wiring (minimal, additive):** the ctor gains keyword-only
  `audit_key: str = DEV_AUDIT_KEY` and `audit_cipher: Cipher = NullCipher()` (defaults keep
  every existing `ResearchService(...)` construction — including all tests — working, now
  dev-key-signed). Each existing `audit.emit(record, self._audit_path)` call becomes
  `audit.emit(record, self._audit_path, key=self._audit_key, cipher=self._audit_cipher)`. **No
  change to retrieval/authz logic, outcomes, or the one-record-per-path invariant.** A signing
  fault is impossible for stdlib HMAC on valid inputs; a *cipher* fault on the opt-in encrypt
  path is wrapped like the sibling store faults (`except … → FETCH_ERROR`, one audit record is
  moot since the fault is at the audit write — see §5.3 note).
- **`deps.get_service`** resolves `audit_key = secret_provider.require("audit_signing_key")`
  (dev default in dev) and `audit_cipher = make_cipher(settings)`.

**Security properties (honest).** `verify_chain` detects: any edit to a past record, reordering,
insertion, and **mid-stream** deletion (the chain breaks at the first altered link; with the
managed HMAC key an attacker without the key cannot forge a repaired chain). It does **not** by
itself detect **tail truncation** (dropping the most recent K records leaves a shorter but valid
chain) — detecting that needs an external anchor (persisted head hash + expected count), which is
out of scope and **documented as a limitation**. An attacker **with** the signing key can rewrite
the whole log — hence the chain's integrity depends on the secret gate (§5.1); the coupling is
intentional. This is tamper-**evidence** (detect), not tamper-**prevention** (block); real WORM
is a deployment control (`chattr +a`, S3 Object Lock), documented in the in-transit/at-rest notes.

### 5.3 Encryption at rest — `crypto/` package

- **`crypto/ports.py`**: `Cipher` Protocol — `encrypt(data: bytes) -> bytes`,
  `decrypt(token: bytes) -> bytes`; `CipherError(Exception)` (type-tag only, no plaintext/key).
- **`crypto/null.py`**: `NullCipher` — identity (`encrypt`/`decrypt` return input). Default ⇒
  audit lines stay plaintext signed JSON ⇒ byte-identical to the §5.2 default format.
- **`crypto/fernet.py`**: `FernetCipher(key: str)` — **lazy `from cryptography.fernet import
  Fernet` inside `__init__`** (importing the module never pulls `cryptography`; missing
  `[crypto]` extra → `CipherError` naming the extra). `encrypt`/`decrypt` wrap Fernet;
  `InvalidToken`/any fault → `CipherError` (type only).
- **`crypto/factory.py`**: `make_cipher(settings) -> Cipher` — `NullCipher` default;
  `FernetCipher(secret_provider.require("audit_encryption_key"))` when `SAIR_CIPHER=fernet`.
- **Applied to the audit log** at the `emit`/`read_records`/`verify_chain` framing boundary
  (sign-then-encrypt: the envelope is sealed, then the line is encrypted; verify decrypts then
  checks). A decrypt fault during `read_records`/`verify_chain` surfaces as `CipherError`
  (caught by the caller as a verification failure, never a 500). The cipher seam is written
  reusable for the nvd-cache/other sinks (follow-on, not wired here).
- `[project.optional-dependencies].crypto = ["cryptography>=43,<47"]`.

### 5.4 Encryption in transit — config + check + docs

- **Config knobs** (§7): `db_sslmode` (default `""` = today's DSN unchanged; e.g. `"require"`),
  `minio_secure` (bool, default False = today), `require_https` (bool, default False).
- **`deps`/DSN**: when `db_sslmode` is set, append `?sslmode=<v>` to `SAIR_DB_URL`; pass
  `secure=minio_secure` to the MinIO client.
- **Startup posture check** `check_transit_posture(settings) -> list[str]` (warnings): flags a
  **non-loopback** DB/MinIO/OIDC endpoint configured **without** TLS (sslmode not require /
  minio_secure False / http:// issuer). In prod mode (`require_strong_secrets`/a `require_https`
  flag) a warning becomes a `SecretError`-style refusal; in dev it logs warnings. Called beside
  `verify_secrets` at startup.
- **Docs**: `docs/phase5-encryption-transit.md` — the TLS boundary (uvicorn/reverse proxy owns
  client↔app TLS), how to enable each knob, and the honest statement that loopback-bound dev
  ports are not LAN-exposed.

### 5.5 Startup wiring & fault model (builder-check Q1/Q2/Q8)

**Startup gate, not per-request.** A FastAPI **lifespan** on `api/main.py` runs once, reading
`get_settings()` (so test cache-clears/overrides apply) + the secret provider:
1. `verify_secrets(settings, provider)` — fail-closed in prod mode (§5.1).
2. `check_transit_posture(settings)` — warn in dev, refuse in prod (§5.4).
3. Eagerly build `get_service()` and read/validate the audit-log head. A **misconfiguration** —
   missing `[crypto]` extra, `cipher=fernet` with no key, or an existing log incompatible with
   the configured key/cipher — surfaces as a **clean boot failure**, never a first-request 500.

`get_service` is `lru_cache`d and built here, so a booted app always holds a valid service with a
resolvable key+cipher. In the **default dev** config every secret is a valid dev placeholder and
`cipher=none`, so the lifespan is a no-op that always succeeds. A bare `TestClient(app)` (no
`with`) does **not** run the lifespan ⇒ existing non-context TestClient tests are unaffected; a
`with TestClient(app)` exercises the gate (dev ⇒ pass).

**`emit` is total at runtime**, so "one record per request, never an unhandled 500" holds.
Signing (`hmac`/`sha256` over a pydantic dump) has no failure mode on valid inputs; the only
raising path is `_chain_head` decrypt/parse, and startup validation + the single-process flock
writer + a consistent key/cipher guarantee the head always parses at runtime. Belt-and-suspenders:
the service wraps `emit` in the same `except Exception → FETCH_ERROR` backstop used for
store/generator faults, and `_emit_terminal` (the fault-path emitter) guards its own `emit` so a
terminal-path audit failure **logs and returns the already-decided outcome** instead of raising a
second exception. An externally corrupted local log mid-run is outside the request-input threat
model (it is what `verify_chain` exists to *detect*), and even then the backstop blocks a 500.

**Offline tools (Q4).** `fetch_cve` (`research_from_source`), `demo/correlation.py`, and
`evaluation/benchmark.py` build their own `ResearchService` with the **default dev key +
NullCipher** and write their **own** log paths, never the API's `settings.audit_log_path`.
`research_from_source` gains optional `audit_key`/`audit_cipher` params (default dev) so a
production CLI run can pass the managed key; mixing keys in one file is the documented
misconfiguration `verify_chain` catches.

**Reading a Fernet log (Q8).** A log written under `FernetCipher` must be read/verified with the
matching cipher; `read_records`/`verify_chain` default to `NullCipher` and raise `CipherError` on
a mismatch. The default path never mixes ciphers (deps builds one), and no default-path consumer
reads audit bytes — `evaluation/benchmark.py` reads pipeline results, not the log (Review Focus 4).

## 6. Config additions (`config.py`, `SAIR_` prefix)

| Setting | Default | Meaning |
|---|---|---|
| `require_strong_secrets` | `False` | Prod gate; True ⇒ `verify_secrets` fails closed on placeholders |
| `secret_provider` | `"env"` | `env` \| `file` |
| `secret_dir` | `Path("secrets")` | dir for `FileSecretProvider` |
| `audit_signing_key` | `DEV_AUDIT_KEY` | HMAC key for the audit chain (a managed secret) |
| `cipher` | `"none"` | `none` \| `fernet` (at-rest cipher) |
| `audit_encryption_key` | `""` | Fernet key (required when `cipher=fernet`) |
| `db_sslmode` | `""` | appended to DB DSN when set |
| `minio_secure` | `False` | MinIO client TLS |
| `require_https` | `False` | in-transit prod gate |

## 7. Test plan / Review Focus

**Review Focus (input classes the tasks' happy-path tests won't exercise):**
1. **Tail truncation is honestly undetected** — a test asserts `verify_chain` returns `ok=True`
   on a truncated-tail log (pinning the documented limitation, so a future reader isn't misled).
2. **Mid-stream tamper is caught at the right seq** — edit record N of M, assert
   `first_bad_seq == N`; reorder two records, assert detection; flip one HMAC byte, assert
   detection via `compare_digest`.
3. **Fail-closed bites only in prod** — `verify_secrets` is a no-op on default dev placeholders,
   raises `SecretError` (not naming the value) when `require_strong_secrets=True`.
4. **Default audit path byte-identical to the signed format, and `read_records` unchanged** —
   existing audit-reading tests still get `ResearchRecord`; the Phase-4 `citation 0.7742 / 1.0`
   regression gate stays green (confirm the gate never reads audit *bytes*).
5. **Opt-in cipher round-trips and never imports `cryptography` by default** — `NullCipher`
   identity; with `cryptography` installed, `FernetCipher` encrypt→decrypt→verify_chain holds;
   `"cryptography" not in sys.modules` after the hermetic suite; missing-extra → `CipherError`
   naming the extra.
6. **Secrets never leak** — a provoked `SecretError`/`CipherError` message contains no secret
   substring; `redact` replaces known secrets.
7. **Canonicalization round-trips (no false tamper)** — a record with a tz-aware
   microsecond-precision `timestamp`, a unicode `objective`, and a float inside
   `tool_invocations` must `verify_chain`-pass after a real write→read: the dump→parse→dump that
   `verify_chain` performs must be byte-idempotent, else every record falsely reads as tampered.

**Live/integration (`-m integration`, skip cleanly):** Fernet round-trip through a real
`cryptography` install; (optional) `sslmode=require` against the live pgvector from Slice 2.

## 8. What's left to the builder

- Exact task decomposition and RED→GREEN steps (the writing-plans skill produces these).
- Whether `_chain_head` reads the whole file or reverse-seeks the last line (either is correct;
  whole-file is simplest and in-scope — note the optimization as a deferred minor).
- Precise placeholder set and the `name→attribute` map in `EnvSecretProvider`.
- The `cryptography` version pin within `>=43,<47` (match what resolves offline).
- Prose for `docs/phase5-encryption-transit.md`.

## 9. Known limitations (stated, by design)

- Tamper-**evidence**, not prevention; no OS-WORM, no external anchor ⇒ tail truncation
  undetected without a persisted head (future).
- HMAC (symmetric) ⇒ the log owner/key-holder can rewrite history; non-repudiation against the
  owner needs Ed25519 (future opt-in).
- At-rest cipher is demonstrated on the audit log only; corpus backends (pgvector/MinIO/NVD
  cache) rely on deployment encryption until a follow-on wires the seam.
- In-transit is config + check + docs; actual TLS termination is the deployment's (uvicorn /
  reverse proxy) responsibility.
