"""Tamper-evident audit chain (Phase 5, Slice 5, Task 3).

Each emitted line is a signed *envelope* around one :class:`ResearchRecord`:

    {seq, prev_hash, record_hash, hmac, record}

``record_hash`` chains SHA-256 over (seq, prev_hash, canonical record), so altering or
reordering any record breaks every link after it; ``hmac`` (HMAC-SHA256 over record_hash with the
managed signing key) means an attacker who cannot read the key cannot forge a valid line.

Honest scope — this is tamper-**evidence**, not WORM:
- **Tail truncation** (dropping the last N records) leaves a shorter but internally-valid chain;
  detecting it needs an external anchor (e.g. periodically publishing the head hash). Out of scope.
- HMAC is **symmetric**: whoever holds the key can rewrite history wholesale. A keyless deployment
  still gets the hash-chain (reorder/edit evidence) but no forgery resistance.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from pydantic import BaseModel

from secure_ai_research.audit.record import ResearchRecord
from secure_ai_research.crypto.null import NullCipher
from secure_ai_research.crypto.ports import Cipher

GENESIS_HASH = "0" * 64
# The well-known dev signing key. verify_secrets refuses it in prod; it MUST stay byte-identical to
# config.Settings.audit_signing_key's default so a dev deployment verifies its own chain.
DEV_AUDIT_KEY = "dev-audit-signing-key-change-me-not-for-production"


class AuditFormatError(ValueError):
    """A line is not a parseable signed envelope (garbled, or an incompatible/legacy head)."""


class AuditEnvelope(BaseModel):
    """The signed wrapper persisted as one JSON line."""

    seq: int
    prev_hash: str
    record_hash: str
    hmac: str
    record: ResearchRecord


class ChainVerification(BaseModel):
    """Outcome of :func:`verify_chain`. ``first_bad_seq`` is the 0-based line index (== seq in a
    valid chain) of the first failing line, or None when ``ok``."""

    ok: bool
    count: int
    first_bad_seq: int | None = None
    reason: str = ""


def canonical_record_bytes(record: ResearchRecord) -> bytes:
    """Deterministic, round-trip-idempotent serialization of a record for hashing.

    Uses ``model_dump(mode="json")`` then a sorted, separator-pinned ``json.dumps`` so that
    dump -> parse -> dump yields identical bytes (pinned by test_canonical_record_bytes_idempotent).
    """
    return json.dumps(
        record.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_record_hash(seq: int, prev_hash: str, record: ResearchRecord) -> str:
    preimage = f"{seq}\n{prev_hash}\n".encode() + canonical_record_bytes(record)
    return hashlib.sha256(preimage).hexdigest()


def compute_hmac(record_hash: str, key: str) -> str:
    return hmac.new(key.encode("utf-8"), record_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def seal(seq: int, prev_hash: str, record: ResearchRecord, key: str) -> AuditEnvelope:
    record_hash = compute_record_hash(seq, prev_hash, record)
    return AuditEnvelope(
        seq=seq,
        prev_hash=prev_hash,
        record_hash=record_hash,
        hmac=compute_hmac(record_hash, key),
        record=record,
    )


def _nonempty(lines: list[bytes]) -> list[bytes]:
    return [line for line in lines if line.strip()]


def parse_chain_head(lines: list[bytes], cipher: Cipher) -> tuple[int, str]:
    """Return ``(last_seq, last_record_hash)`` for the existing chain.

    ``(-1, GENESIS_HASH)`` when empty. A non-empty but unparseable/incompatible last line raises
    :class:`AuditFormatError` — the writer refuses to fork a new seq-0 chain onto a head it cannot
    read (no-silent-fork), rather than silently starting over.
    """
    items = _nonempty(lines)
    if not items:
        return (-1, GENESIS_HASH)
    try:
        env = AuditEnvelope.model_validate_json(cipher.decrypt(items[-1]))
    except Exception as exc:
        raise AuditFormatError("audit log head is not a compatible signed envelope") from exc
    return (env.seq, env.record_hash)


def verify_chain(path: Path, key: str, *, cipher: Cipher | None = None) -> ChainVerification:
    """Verify the whole chain at ``path``: seq order, prev_hash links, record hashes, and HMACs."""
    cipher = cipher or NullCipher()
    path = Path(path)
    if not path.exists():
        return ChainVerification(ok=True, count=0)
    lines = _nonempty(path.read_bytes().splitlines())
    prev = GENESIS_HASH
    for i, raw in enumerate(lines):
        try:
            env = AuditEnvelope.model_validate_json(cipher.decrypt(raw))
        except Exception:
            return ChainVerification(ok=False, count=i, first_bad_seq=i, reason="unparseable line")
        if env.seq != i:
            return ChainVerification(ok=False, count=i, first_bad_seq=i, reason="seq out of order")
        if env.prev_hash != prev:
            return ChainVerification(ok=False, count=i, first_bad_seq=i, reason="broken prev_hash")
        if compute_record_hash(env.seq, env.prev_hash, env.record) != env.record_hash:
            return ChainVerification(
                ok=False, count=i, first_bad_seq=i, reason="record hash mismatch"
            )
        if not hmac.compare_digest(compute_hmac(env.record_hash, key), env.hmac):
            return ChainVerification(ok=False, count=i, first_bad_seq=i, reason="hmac mismatch")
        prev = env.record_hash
    return ChainVerification(ok=True, count=len(lines))
