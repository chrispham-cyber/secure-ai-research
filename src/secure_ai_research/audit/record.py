"""Research / audit records (design §5.5).

Each record captures enough to reconstruct one AI-assisted analysis: the analyst,
the model and prompt versions, the data sources and their hashes, the retrieved
documents, tool calls, output, validation, reviewer, and conclusion. Records are
written **append-only** as JSON Lines so the trail cannot be silently rewritten.

Note: for sensitive environments, the log must not copy protected prompts or
content into unauthorized stores — see ``security-controls/audit/``.
"""

from __future__ import annotations

import fcntl
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from secure_ai_research.crypto.null import NullCipher
from secure_ai_research.crypto.ports import Cipher

# Serializes emit() within one process; fcntl.flock serializes across processes. Together they make
# the read-head / append-sealed-line sequence atomic so concurrent writers cannot fork the chain.
_EMIT_LOCK = threading.Lock()


class ResearchRecord(BaseModel):
    """One reconstructable AI-assisted analysis."""

    research_id: str
    analyst_id: str
    timestamp: datetime
    objective: str
    data_source_ids: list[str] = Field(default_factory=list)
    document_hashes: list[str] = Field(default_factory=list)
    model_id: str
    model_version: str
    prompt_template_version: str
    retrieved_doc_ids: list[str] = Field(default_factory=list)
    tool_invocations: list[dict[str, Any]] = Field(default_factory=list)
    model_output: str = ""
    validation_results: dict[str, Any] = Field(default_factory=dict)
    reviewer: str | None = None
    conclusion: str = ""


def emit(record: ResearchRecord, path: Path, *, key: str, cipher: Cipher | None = None) -> None:
    """Append ``record`` as one signed (and optionally encrypted) envelope line to ``path``.

    Reads the current chain head under an exclusive lock, seals ``record`` onto it with ``key``,
    then appends ``cipher.encrypt(envelope_json) + b"\\n"``. ``key`` is required so no caller emits
    an unsigned line; ``cipher`` defaults to :class:`NullCipher` (plaintext-signed, byte-identical
    to the legacy format minus the envelope wrapper).
    """
    from secure_ai_research.audit.signing import parse_chain_head, seal

    cipher = cipher or NullCipher()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _EMIT_LOCK, open(path, "a+b") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.seek(0)
        last_seq, prev_hash = parse_chain_head(handle.read().splitlines(), cipher)
        envelope = seal(last_seq + 1, prev_hash, record, key)
        line = cipher.encrypt(envelope.model_dump_json().encode("utf-8")) + b"\n"
        handle.seek(0, 2)
        handle.write(line)
        handle.flush()
        # flock is released when the handle closes at the end of the with-block.


def read_records(path: Path, *, cipher: Cipher | None = None) -> list[ResearchRecord]:
    """Read all records from a signed audit file (empty list if absent).

    Unwraps each envelope to its :class:`ResearchRecord`. A legacy bare-record line (pre-signing)
    is tolerated for viewing only. This does NOT verify the chain — use
    :func:`secure_ai_research.audit.signing.verify_chain` for that.
    """
    from secure_ai_research.audit.signing import AuditEnvelope

    cipher = cipher or NullCipher()
    path = Path(path)
    if not path.exists():
        return []
    records: list[ResearchRecord] = []
    for raw in path.read_bytes().splitlines():
        if not raw.strip():
            continue
        decrypted = cipher.decrypt(raw)
        try:
            records.append(AuditEnvelope.model_validate_json(decrypted).record)
        except Exception:
            records.append(ResearchRecord.model_validate_json(decrypted))  # legacy bare line
    return records
