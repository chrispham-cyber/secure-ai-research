"""Tamper-evident signed audit chain (Phase 5, Slice 5, Task 3)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from secure_ai_research.audit.record import ResearchRecord, emit, read_records
from secure_ai_research.audit.signing import (
    DEV_AUDIT_KEY,
    AuditFormatError,
    canonical_record_bytes,
    parse_chain_head,
    verify_chain,
)
from secure_ai_research.config import Settings
from secure_ai_research.crypto.null import NullCipher

K = "test-signing-key-0123456789"


def _rec(**kw) -> ResearchRecord:
    fields = dict(
        research_id="R-1",
        analyst_id="a-1",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        objective="o",
        model_id="m",
        model_version="v",
        prompt_template_version="pv",
    )
    fields.update(kw)
    return ResearchRecord(**fields)


def test_emit_then_read_returns_research_record(tmp_path):
    p = tmp_path / "a.jsonl"
    r = _rec(objective="hello")
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
    env = json.loads(lines[1])
    env["record"]["objective"] = "EVIL"
    lines[1] = json.dumps(env).encode()
    p.write_bytes(b"\n".join(lines) + b"\n")
    v = verify_chain(p, K)
    assert not v.ok and v.first_bad_seq == 1


def test_reordered_records_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    for i in range(3):
        emit(_rec(objective=f"o{i}"), p, key=K)
    lines = p.read_bytes().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    p.write_bytes(b"\n".join(lines) + b"\n")
    assert not verify_chain(p, K).ok


def test_flipped_hmac_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    emit(_rec(), p, key=K)
    lines = p.read_bytes().splitlines()
    env = json.loads(lines[0])
    h = env["hmac"]
    env["hmac"] = ("0" if h[0] != "0" else "1") + h[1:]
    lines[0] = json.dumps(env).encode()
    p.write_bytes(b"\n".join(lines) + b"\n")
    assert not verify_chain(p, K).ok


def test_tail_truncation_not_detected(tmp_path):
    # Honest limitation: dropping the last record leaves a shorter but valid chain.
    p = tmp_path / "a.jsonl"
    for i in range(3):
        emit(_rec(objective=f"o{i}"), p, key=K)
    lines = p.read_bytes().splitlines()
    p.write_bytes(b"\n".join(lines[:-1]) + b"\n")
    v = verify_chain(p, K)
    assert v.ok and v.count == 2


def test_wrong_key_fails_verification(tmp_path):
    p = tmp_path / "a.jsonl"
    emit(_rec(), p, key=K)
    assert not verify_chain(p, "other-key-0123456789abcd").ok


def test_canonical_record_bytes_idempotent():
    r = _rec(
        timestamp=datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC),
        objective="übér",
        tool_invocations=[{"score": 0.5}],
    )
    assert canonical_record_bytes(r) == canonical_record_bytes(
        ResearchRecord.model_validate(r.model_dump(mode="json"))
    )


def test_chain_head_rejects_incompatible_line():
    with pytest.raises(AuditFormatError):
        parse_chain_head([_rec().model_dump_json().encode()], NullCipher())


def test_read_records_tolerates_legacy_bare_line(tmp_path):
    p = tmp_path / "a.jsonl"
    r = _rec()
    p.write_bytes(r.model_dump_json().encode() + b"\n")
    assert read_records(p) == [r]


def test_dev_audit_key_matches_config_default():
    assert Settings().audit_signing_key == DEV_AUDIT_KEY
