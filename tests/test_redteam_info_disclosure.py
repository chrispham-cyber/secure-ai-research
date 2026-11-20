"""Information-disclosure red-team eval: zero RESTRICTED leak on every path (Week 15)."""

import pytest

from secure_ai_research.agents.functions import AgentToolset
from secure_ai_research.evaluation.benchmark import (
    RESTRICTED_CANARY,
    RESTRICTED_DOC_ID,
    build_benchmark_service,
)
from secure_ai_research.evaluation.redteam import run_info_disclosure_eval
from secure_ai_research.research_service import Outcome


@pytest.fixture
def service(tmp_path):
    return build_benchmark_service(tmp_path / "a.jsonl")


def test_zero_disclosures_across_all_paths(service):
    r = run_info_disclosure_eval(service)
    assert r.disclosures == 0 and r.failures == ()
    assert r.probes >= 4  # id-route, search, toolset id-route, toolset search


def test_restricted_doc_is_really_senior_readable(service):  # Review Focus 3 (positive control)
    res = service.research_cve(RESTRICTED_DOC_ID, role="senior_analyst")
    assert res.outcome is Outcome.OK and RESTRICTED_CANARY in res.answer


def test_info_disclosure_byte_identical_not_status(service):  # Review Focus 1
    # research_analyst sees a present-RESTRICTED id exactly as a genuinely-absent id,
    # not merely "also NOT_FOUND": same answer and citations (not just same status).
    present = service.research_cve(RESTRICTED_DOC_ID, role="research_analyst")
    absent = service.research_cve("CVE-2099-9999", role="research_analyst")
    assert present.outcome == absent.outcome == Outcome.NOT_FOUND
    assert present.answer == absent.answer == ""
    cites = lambda r: [(c.document_id, c.source_url, c.passage) for c in r.citations]  # noqa: E731
    assert cites(present) == cites(absent) == []


def test_info_disclosure_search_probe_is_not_canary_and_does_not_leak(service):  # Review Focus 5
    from secure_ai_research.evaluation import redteam

    assert RESTRICTED_CANARY not in redteam._RESTRICTED_PROBE_QUERY
    s = service.search(redteam._RESTRICTED_PROBE_QUERY, role="research_analyst")
    assert RESTRICTED_DOC_ID not in {c.document_id for c in s.citations}
    assert RESTRICTED_CANARY not in s.answer


def test_toolset_path_also_zero_disclosure(service):
    tools = AgentToolset(service, role="research_analyst")
    assert RESTRICTED_CANARY not in tools.search_cve(RESTRICTED_DOC_ID).answer
    assert RESTRICTED_CANARY not in tools.search_research("sensitive internal incident").answer
