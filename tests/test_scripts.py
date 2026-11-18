import subprocess
import sys
from pathlib import Path

from secure_ai_research.audit.record import ResearchRecord, read_records

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "new_research_record.py"


def test_new_research_record_emits_template():
    result = subprocess.run(
        [sys.executable, "-I", str(SCRIPT)],
        capture_output=True,
        text=True,
        check=True,
    )
    record = ResearchRecord.model_validate_json(result.stdout)
    assert record.research_id == ""
    assert record.analyst_id == ""
    assert record.objective == ""
    assert record.model_id == ""
    assert record.data_source_ids == []
    assert record.reviewer is None
    assert record.conclusion == ""


def test_new_research_record_output_appends_to_jsonl(tmp_path):
    # The documented workflow appends the output straight to the append-only
    # JSON Lines audit log, so the output must be exactly one JSON line.
    result = subprocess.run(
        [sys.executable, "-I", str(SCRIPT)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "\n" not in result.stdout.strip()

    log = tmp_path / "research-records.jsonl"
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(result.stdout)
    records = read_records(log)
    assert len(records) == 1
    assert records[0].research_id == ""
