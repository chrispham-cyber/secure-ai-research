"""Tests for the labeled synthetic prompt-injection corpus (ROADMAP Phase 3, Week 11)."""

from secure_ai_research.evaluation.injection_corpus import malicious_corpus
from secure_ai_research.ingestion.schema import Classification


def test_corpus_is_clearly_labeled_and_valid():
    docs = malicious_corpus()
    ids = {d.document.document_id for d in docs}
    assert ids == {"INJ-FORGED-CITATION", "INJ-IMPERSONATE", "INJ-INSTRUCTION", "INJ-ESCALATION"}
    for d in docs:
        assert d.document.document_id.startswith("INJ-")  # namespaced, search-only
        assert d.document.source == "synthetic-injection-corpus"  # clearly labeled
        assert d.document.classification is Classification.PUBLIC
        assert d.text.strip()


def test_corpus_carries_the_injection_payloads():
    by_id = {d.document.document_id: d.text for d in malicious_corpus()}
    assert "[CVE-0000-0001]" in by_id["INJ-FORGED-CITATION"]  # forged citation marker
    assert "[CVE-2021-44228]" in by_id["INJ-IMPERSONATE"]  # impersonates a real id
    assert "ignore all previous instructions" in by_id["INJ-INSTRUCTION"].lower()
    assert "senior_analyst" in by_id["INJ-ESCALATION"]  # authz-escalation lure
