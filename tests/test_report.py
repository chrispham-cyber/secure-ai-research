from datetime import UTC, datetime

from secure_ai_research.audit.record import ResearchRecord
from secure_ai_research.reporting.report import build_report


def _record(model_output: str, retrieved_doc_ids: list[str]) -> ResearchRecord:
    return ResearchRecord(
        research_id="r1",
        analyst_id="research_analyst",
        timestamp=datetime(2099, 1, 1, tzinfo=UTC),
        objective="Correlate CVE-2099-0001 against public sources",
        model_id="retrieval-only",
        model_version="",
        prompt_template_version="",
        retrieved_doc_ids=retrieved_doc_ids,
        model_output=model_output,
    )


def test_report_includes_cited_claim():
    out = build_report(_record("A synthetic SQL injection. [CVE-2099-0001]", ["CVE-2099-0001"]))
    assert "A synthetic SQL injection." in out
    assert "CVE-2099-0001" in out
    assert "Correlate CVE-2099-0001" in out  # objective rendered


def test_uncited_claim_line_dropped():
    out = build_report(
        _record(
            "Cited thing. [CVE-2099-0001]\nUncited editorializing with no citation.",
            ["CVE-2099-0001"],
        )
    )
    assert "Cited thing." in out
    assert "Uncited editorializing" not in out


def test_claim_citing_unknown_id_dropped():
    out = build_report(_record("Mystery claim. [CVE-2099-9999]", ["CVE-2099-0001"]))
    assert "Mystery claim." not in out


def test_no_cited_claims_states_no_findings():
    out = build_report(_record("", ["CVE-2099-0001"]))
    assert "No cited findings." in out
