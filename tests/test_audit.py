from datetime import datetime

from secure_ai_research.audit.record import ResearchRecord, emit, read_records

# emit() now requires a signing key (Slice 5). These legacy tests exercise append/round-trip, not
# signing, so any strong key works; signing behaviour is covered by tests/test_audit_signing.py.
_K = "test-audit-key-0123456789"


def make_record(**overrides) -> ResearchRecord:
    fields = {
        "research_id": "R-001",
        "analyst_id": "analyst-1",
        "timestamp": datetime(2026, 11, 18, 12, 0, 0),
        "objective": "correlate CVE-2026-0001 with ATT&CK",
        "model_id": "example/local-llm",
        "model_version": "0.0.0-synthetic",
        "prompt_template_version": "v1",
    }
    fields.update(overrides)
    return ResearchRecord(**fields)


def test_emit_creates_path(tmp_path):
    path = tmp_path / "nope" / "audit.jsonl"
    emit(make_record(), path, key=_K)
    assert path.exists()


def test_emit_appends(tmp_path):
    path = tmp_path / "audit.jsonl"
    emit(make_record(research_id="R-001"), path, key=_K)
    emit(make_record(research_id="R-002"), path, key=_K)
    records = read_records(path)
    assert [r.research_id for r in records] == ["R-001", "R-002"]


def test_roundtrip_fields(tmp_path):
    path = tmp_path / "audit.jsonl"
    rec = make_record(
        tool_invocations=[{"tool": "search_cve", "args": {"id": "CVE-2026-0001"}}],
        validation_results={"citations_ok": True},
        reviewer="team-lead",
        conclusion="confirmed",
    )
    emit(rec, path, key=_K)
    loaded = read_records(path)
    assert len(loaded) == 1
    assert loaded[0] == rec
