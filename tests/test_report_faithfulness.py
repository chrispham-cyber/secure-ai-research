"""Faithfulness floor in build_report (Phase 5, Slice 1a, Task 3).

A line can cite a genuinely-retrieved id yet make a claim the passage does not support
(anti-goal A1: "valid id + invented text"). With the cited passages supplied, build_report
additionally drops any line whose claim tokens overlap its cited passages below a lenient
floor. Passing ``passages=None`` keeps today's behavior exactly (byte-identity, G3).
"""

from __future__ import annotations

from datetime import UTC, datetime

from secure_ai_research.audit.record import ResearchRecord
from secure_ai_research.reporting.report import build_report


def _rec(model_output: str, retrieved: list[str]) -> ResearchRecord:
    return ResearchRecord(
        research_id="r",
        analyst_id="a",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        objective="obj",
        model_id="ollama",
        model_version="mistral:latest",
        prompt_template_version="v1",
        retrieved_doc_ids=retrieved,
        model_output=model_output,
    )


def test_passages_none_is_unchanged():  # G3 guard
    rec = _rec("Some finding about the flaw [CVE-2021-44228]", ["CVE-2021-44228"])
    expected = (
        "# Research report: obj\n\n"
        "Some finding about the flaw [CVE-2021-44228]\n\n"
        "Sources: CVE-2021-44228"
    )
    assert build_report(rec) == expected
    assert build_report(rec, None) == expected


def test_invented_claim_with_valid_id_is_dropped():  # RF3 / anti-goal A1
    rec = _rec("Remote code execution confirmed [CVE-2021-44228]", ["CVE-2021-44228"])
    passages = {"CVE-2021-44228": ["Log4j JNDI lookup logging library issue"]}
    report = build_report(rec, passages)
    assert "Remote code execution confirmed" not in report
    assert "No cited findings." in report


def test_passage_text_line_is_kept():
    passage = "Log4j JNDI lookup allows remote class loading"
    rec = _rec(f"{passage} [CVE-2021-44228]", ["CVE-2021-44228"])
    passages = {"CVE-2021-44228": [passage]}
    assert passage in build_report(rec, passages)


def test_faithful_paraphrase_is_kept():
    passage = "Log4j JNDI lookup allows remote class loading from an attacker server"
    rec = _rec("Log4j JNDI lookup enables remote loading [CVE-2021-44228]", ["CVE-2021-44228"])
    passages = {"CVE-2021-44228": [passage]}
    assert "Log4j JNDI lookup enables remote loading" in build_report(rec, passages)
