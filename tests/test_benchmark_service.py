"""Benchmark service builder (ROADMAP Phase 4, Week 14)."""

from secure_ai_research.evaluation.benchmark import (
    RESTRICTED_DOC_ID,
    build_benchmark_service,
)
from secure_ai_research.research_service import Outcome


def test_build_benchmark_service_indexes_all_sources(tmp_path):
    svc = build_benchmark_service(tmp_path / "audit.jsonl")
    # ROUTINE docs any authorized role can see.
    assert svc.research_cve("CVE-2099-0001", role="research_analyst").outcome is Outcome.OK
    assert svc.research_attack("T1059", role="research_analyst").outcome is Outcome.OK
    r = svc.search("log4j", role="research_analyst")
    assert "KEV-CVE-2021-44228" in {c.document_id for c in r.citations}


def test_restricted_doc_present_and_senior_only(tmp_path):
    svc = build_benchmark_service(tmp_path / "audit.jsonl")
    assert svc.research_cve(RESTRICTED_DOC_ID, role="senior_analyst").outcome is Outcome.OK
    assert svc.research_cve(RESTRICTED_DOC_ID, role="research_analyst").outcome is Outcome.NOT_FOUND


def test_benchmark_service_is_offline(tmp_path):
    # No fetcher: an absent CVE is NOT_FOUND, never fetched.
    svc = build_benchmark_service(tmp_path / "audit.jsonl")
    assert svc.research_cve("CVE-2099-9999", role="research_analyst").outcome is Outcome.NOT_FOUND
