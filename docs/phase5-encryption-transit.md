# Phase 5 — Encryption, Secrets & Transit Posture

This platform defaults to an **offline, deterministic, stdlib-only** posture. Every security
control below is additive and opt-in: the default path is byte-identical to pre-Slice-5 behaviour,
and the hermetic test suite never imports a networking or crypto dependency.

## In transit

The app does **not** terminate TLS itself. The client ↔ app hop is owned by uvicorn (with a
cert) or, in production, a reverse proxy / ingress in front of it. `SAIR_REQUIRE_HTTPS=true`
records that intent for the startup gate; it does not itself encrypt anything.

What the app *can* set is the transport for its own outbound backends. `check_transit_posture()`
(in `transit.py`) returns one advisory warning per **active, non-loopback** backend whose link
lacks TLS:

| Backend | Active when | Warns unless |
|---|---|---|
| pgvector (Postgres) | `SAIR_VECTOR_STORE=pgvector` | `SAIR_DB_SSLMODE=require` (or `sslmode=require` already in `SAIR_DB_URL`) |
| MinIO (object store) | `SAIR_OBJECT_STORE=minio` | `SAIR_MINIO_SECURE=true` |
| OIDC issuer | `SAIR_AUTH=oidc` | issuer URL is `https://` (or loopback) |

`apply_sslmode(db_url, sslmode)` appends `sslmode=<mode>` to the DSN (unless already present); the
pgvector factory applies it automatically. MinIO's `secure=` flag is wired from `SAIR_MINIO_SECURE`.

**Dev posture:** the bundled docker-compose binds every service port to `127.0.0.1`, so a loopback
dev stack produces **no** warnings — traffic never leaves the host. Warnings appear only once a
backend points at a real remote host without TLS.

## At rest

The audit log is **signed by default** (see below) and can additionally be **encrypted at rest**
with `SAIR_CIPHER=fernet` (requires the `crypto` extra: `pip install -e '.[crypto]'`). The default
`SAIR_CIPHER=none` keeps lines as plaintext-signed JSON. The Fernet key is a managed secret
(`SAIR_AUDIT_ENCRYPTION_KEY`); a prod deployment that enables the cipher must set a strong one.

Database/object-store at-rest encryption is the responsibility of the storage layer (Postgres TDE
/ volume encryption, MinIO SSE) and is out of scope for the app.

## Secrets

Secrets resolve through a `SecretProvider` seam (`secret/`): `env` (default, reads `SAIR_*`) or
`file` (`SAIR_SECRET_PROVIDER=file`, one file per secret under `SAIR_SECRET_DIR`). In production
(`SAIR_REQUIRE_STRONG_SECRETS=true`) the startup gate `verify_secrets()` **fails closed** on any
active placeholder or too-short secret, naming the offending setting (never its value), and
overrides `SAIR_AUTH_ALLOW_DEV_SECRET`.

## Audit signing — one key per log file

The tamper-evident chain (`audit/signing.py`) HMACs each record under `SAIR_AUDIT_SIGNING_KEY`.
**A given audit log file is sealed and verified with exactly one key.** Rotating the key means
starting a new log file (or re-sealing an archived one under the new key); mixing keys within one
file makes the tail unverifiable. If the cipher is enabled, the file must be *read back* with the
matching cipher too.

## Honest limitations (spec §9)

- This is tamper-**evidence**, not WORM. An attacker with write access to the log can **truncate
  the tail** (drop the last N records) and leave a shorter but internally-valid chain. Detecting
  truncation needs an **external anchor** — e.g. periodically publishing the head hash to a
  separate store. Out of scope for this slice.
- HMAC is **symmetric**: whoever holds the signing key can rewrite history wholesale and re-sign.
  The chain resists forgery only against parties who cannot read the key. A keyless deployment
  still detects accidental edits/reorders via the hash-chain, but has no forgery resistance.
- The signed envelope protects the audit trail, not the primary data stores; row-level integrity
  in Postgres/MinIO is their own concern.
