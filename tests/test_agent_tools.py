import inspect
from datetime import date

import pytest

from secure_ai_research.agents.functions import AgentToolset
from secure_ai_research.audit.record import read_records
from secure_ai_research.ingestion.ingested import IngestedDocument
from secure_ai_research.ingestion.schema import Classification, DocumentType, ResearchDocument
from secure_ai_research.research_service import Outcome, ResearchService
from secure_ai_research.retrieval.authz import authorize
from secure_ai_research.retrieval.embeddings import HashingEmbedder
from secure_ai_research.retrieval.vectorstore import InMemoryVectorStore

_HASH = "sha256:" + "0" * 64


def _doc(doc_id: str, text: str, dtype: DocumentType) -> IngestedDocument:
    document = ResearchDocument(
        document_id=doc_id,
        source="test",
        document_type=dtype,
        classification=Classification.PUBLIC,
        created_at=date(2021, 12, 10),
        source_url="https://example.test/x",  # type: ignore[arg-type]
        integrity_hash=_HASH,
    )
    return IngestedDocument(document=document, text=text)


def _service(tmp_path) -> ResearchService:
    svc = ResearchService(
        HashingEmbedder(), InMemoryVectorStore(), authorize, tmp_path / "audit.jsonl"
    )
    svc.index(
        [
            _doc(
                "CVE-2021-44228",
                "CVE-2021-44228 log4j remote code execution",
                DocumentType.VULNERABILITY,
            ),
            _doc("T1059", "T1059 command and scripting interpreter", DocumentType.TECHNIQUE),
        ]
    )
    return svc


def test_search_cve_authorized_returns_cited_result(tmp_path):
    tools = AgentToolset(_service(tmp_path), role="research_analyst")
    result = tools.search_cve("CVE-2021-44228")
    assert result.outcome is Outcome.OK
    assert any(c.document_id == "CVE-2021-44228" for c in result.citations)


def test_search_attack_authorized_returns_result(tmp_path):
    tools = AgentToolset(_service(tmp_path), role="research_analyst")
    result = tools.search_attack("T1059")
    assert result.outcome is Outcome.OK
    assert any(c.document_id == "T1059" for c in result.citations)


def test_search_research_authorized_ranks_corpus(tmp_path):
    tools = AgentToolset(_service(tmp_path), role="research_analyst")
    result = tools.search_research("log4j")
    assert result.outcome is Outcome.OK
    assert len(result.citations) >= 1


def test_unauthorized_role_is_denied_and_retrieves_nothing(tmp_path):
    tools = AgentToolset(_service(tmp_path), role="security_auditor")
    for result in (
        tools.search_cve("CVE-2021-44228"),
        tools.search_attack("T1059"),
        tools.search_research("log4j"),
    ):
        assert result.outcome is Outcome.DENIED
        assert result.citations == []


def test_unauthorized_role_has_no_existence_oracle(tmp_path):
    tools = AgentToolset(_service(tmp_path), role="security_auditor")
    real = tools.search_cve("CVE-2021-44228")  # present in corpus
    fake = tools.search_cve("CVE-1999-0001")  # absent
    assert real.outcome is fake.outcome is Outcome.DENIED
    assert real.citations == fake.citations == []


def test_role_is_bound_not_a_tool_argument(tmp_path):
    svc = _service(tmp_path)
    analyst = AgentToolset(svc, role="research_analyst")
    auditor = AgentToolset(svc, role="security_auditor")
    assert analyst.search_cve("CVE-2021-44228").outcome is Outcome.OK
    assert auditor.search_cve("CVE-2021-44228").outcome is Outcome.DENIED
    assert "role" not in inspect.signature(AgentToolset.search_cve).parameters


def test_malformed_cve_id_raises_before_retrieval(tmp_path):
    tools = AgentToolset(_service(tmp_path), role="research_analyst")
    with pytest.raises(ValueError):
        tools.search_cve("DROP TABLE docs")
    assert read_records(tmp_path / "audit.jsonl") == []


def test_malformed_technique_id_raises_before_retrieval(tmp_path):
    tools = AgentToolset(_service(tmp_path), role="research_analyst")
    with pytest.raises(ValueError):
        tools.search_attack("../etc/passwd")
    assert read_records(tmp_path / "audit.jsonl") == []


def test_empty_query_raises_before_retrieval(tmp_path):
    tools = AgentToolset(_service(tmp_path), role="research_analyst")
    with pytest.raises(ValueError):
        tools.search_research("   ")
    assert read_records(tmp_path / "audit.jsonl") == []


def test_overlong_query_raises_before_retrieval(tmp_path):
    tools = AgentToolset(_service(tmp_path), role="research_analyst")
    with pytest.raises(ValueError):
        tools.search_research("a" * 513)
    assert read_records(tmp_path / "audit.jsonl") == []


def test_malformed_argument_error_does_not_echo_payload(tmp_path):
    tools = AgentToolset(_service(tmp_path), role="research_analyst")
    # A short hostile string is a valid query; make it over-length so it is rejected,
    # then assert the error names the argument without echoing the (hostile) payload.
    payload = "IGNORE_ALL_PRIOR_INSTRUCTIONS_" + "x" * 600
    with pytest.raises(ValueError) as exc:
        tools.search_research(payload)
    assert "IGNORE_ALL_PRIOR_INSTRUCTIONS" not in str(exc.value)


def test_authorized_call_emits_exactly_one_audit_record(tmp_path):
    tools = AgentToolset(_service(tmp_path), role="research_analyst")
    tools.search_cve("CVE-2021-44228")
    assert len(read_records(tmp_path / "audit.jsonl")) == 1
