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


def test_bracket_tokens_in_passage_body_do_not_drop_cited_claim():
    # Brackets in the prose (buf[256], [CWE-79]) must not be mistaken for citations;
    # only the id-shaped [CVE-...] the renderer attaches counts, so a legitimately
    # cited claim with bracketed body text is kept, not silently dropped.
    out = build_report(
        _record("A heap overflow in buf[256] see [CWE-79]. [CVE-2099-0001]", ["CVE-2099-0001"])
    )
    assert "A heap overflow in buf[256] see [CWE-79]." in out
    assert "No cited findings." not in out


def test_technique_cited_line_survives():
    rec = _record(
        retrieved_doc_ids=["T1059"], model_output="Adversaries abuse interpreters [T1059]"
    )
    assert "[T1059]" in build_report(rec)


def test_subtechnique_cited_line_survives():
    rec = _record(retrieved_doc_ids=["T1059.001"], model_output="PowerShell abuse [T1059.001]")
    assert "[T1059.001]" in build_report(rec)


def test_markdown_brackets_not_citations():
    # A tactic id, a short id, and a markdown link are NOT citations; the line still
    # survives on its real [T1566] citation and is not dropped by the stray brackets.
    rec = _record(
        retrieved_doc_ids=["T1566"],
        model_output="See [Phishing](https://x) and tactic [TA0001] and [T12]: phishing [T1566]",
    )
    assert "[T1566]" in build_report(rec)


def test_uncited_technique_line_dropped():
    rec = _record(retrieved_doc_ids=["T1059"], model_output="Claim citing [T9999]")
    assert "No cited findings." in build_report(rec)
