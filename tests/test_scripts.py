import subprocess
import sys
from pathlib import Path

from secure_ai_research.audit.record import ResearchRecord

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
